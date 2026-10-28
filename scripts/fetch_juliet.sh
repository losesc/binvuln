set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
SRC="$ROOT/targets"
CACHE="$ROOT/build/juliet_cache"

JULIET_URL="https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip"
JULIET_SHA256="ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb"
ZIP="$CACHE/juliet_c_cpp_v1.3.zip"
JROOT="$CACHE/src/C"

limit=0
while [ $# -gt 0 ]; do
    case "$1" in
        --limit) limit="${2:?--limit needs a number}"; shift 2 ;;
        --limit=*) limit="${1#--limit=}"; shift ;;
        -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
case "$limit" in ''|*[!0-9]*) echo "--limit must be a non-negative integer" >&2; exit 2 ;; esac

shopt -s nullglob
for c in "$SRC"/*.c; do
    case "$(basename "$c")" in
        j[0-9][0-9][0-9][0-9].c) ;;
        *) echo "targets/ contains non-Juliet target $(basename "$c"); move it aside (e.g. targets/handwritten/) first" >&2
           exit 1 ;;
    esac
done

mkdir -p "$CACHE"
if [ ! -f "$ZIP" ]; then
    echo "Downloading Juliet C/C++ v1.3 from $JULIET_URL"
    curl -sSL --fail -o "$ZIP.part" "$JULIET_URL"
    mv "$ZIP.part" "$ZIP"
fi
got="$(sha256sum "$ZIP" | cut -d' ' -f1)"
if [ "$got" != "$JULIET_SHA256" ]; then
    echo "sha256 mismatch for $ZIP: got $got, expected $JULIET_SHA256" >&2
    exit 1
fi
if [ ! -d "$JROOT/testcases" ]; then
    rm -rf "$CACHE/src"
    unzip -q "$ZIP" -d "$CACHE/src"
fi
echo "Juliet: $JROOT (sha256 $got)"

rm -f "$SRC"/j[0-9][0-9][0-9][0-9].c
mkdir -p "$SRC/juliet_support"
python3 -I - "$JROOT" "$SRC" "$limit" "$JULIET_URL" "$got" <<'PY'
import csv, os, re, sys

jroot, out, limit, url, sha = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5]
tc_dir = os.path.join(jroot, "testcases")
sup_dir = os.path.join(jroot, "testcasesupport")

# Juliet folder -> (CWE id, name, our class). Names follow Juliet's own wording.
CWES = {
    "CWE121": ("CWE-121", "Stack-based Buffer Overflow", "buffer_overflow"),
    "CWE122": ("CWE-122", "Heap-based Buffer Overflow", "buffer_overflow"),
    "CWE124": ("CWE-124", "Buffer Underwrite", "buffer_overflow"),
    "CWE787": ("CWE-787", "Out-of-bounds Write", "buffer_overflow"),
    "CWE134": ("CWE-134", "Uncontrolled Format String", "format_string"),
    "CWE415": ("CWE-415", "Double Free", "use_after_free"),
    "CWE416": ("CWE-416", "Use After Free", "use_after_free"),
}
CLASSES = ["buffer_overflow", "format_string", "use_after_free"]
NONDET = re.compile(r"rand|socket|fgets|fscanf|w32|environment|_file_|listen|connect")

TOKENS = re.compile(r'//[^\n]*|/\*.*?\*/|L?"(?:\\.|[^"\\\n])*"|L?\'(?:\\.|[^\'\\\n])*\'', re.S)

def strip_comments(s):
    return TOKENS.sub(lambda m: " " if m.group(0).startswith("/") else m.group(0), s)

def match_brace(s, i):
    """index just past the } matching the { at s[i], skipping string/char literals"""
    depth = 0
    while i < len(s):
        m = TOKENS.match(s, i)
        if m:
            i = m.end(); continue
        if s[i] == "{": depth += 1
        elif s[i] == "}":
            depth -= 1
            if depth == 0: return i + 1
        i += 1
    raise ValueError("unbalanced braces")

FUNC_HEAD = re.compile(r"^(static\s+)?void\s+(\w+)\s*\(\s*(void)?\s*\)\s*\{", re.M)

def convert(path):
    """-> (prelude, bad_body, good_body, good_name) or raise ValueError(reason)"""
    s = strip_comments(open(path, errors="replace").read())
    s = s.split("#ifdef INCLUDEMAIN")[0]
    if "#ifndef OMITBAD" not in s:
        raise ValueError("no OMITBAD block")
    prelude, rest = s.split("#ifndef OMITBAD", 1)
    funcs, residue, pos = {}, [], 0
    for m in FUNC_HEAD.finditer(rest):
        if m.start() < pos: continue
        end = match_brace(rest, m.end() - 1)
        residue.append(rest[pos:m.start()])
        funcs[m.group(2)] = rest[m.end() - 1:end]
        pos = end
    residue.append(rest[pos:])
    # anything at top level besides the functions and #if/#endif means shared
    # state between functions -> not a single-function testcase
    leftover = [l for l in "".join(residue).splitlines()
                if l.strip() and not re.match(r"\s*#\s*(ifndef|ifdef|endif|else)\b", l)]
    if leftover:
        raise ValueError("extra top-level code: " + leftover[0].strip()[:60])
    bad = [n for n in funcs if n.endswith("_bad")]
    if len(bad) != 1:
        raise ValueError("no unique bad()")
    good_name = next((n for n in ("goodG2B", "goodB2G", "good1") if n in funcs), None)
    if not good_name:
        raise ValueError("no goodG2B/goodB2G/good1")
    local = set(funcs)
    for name in (bad[0], good_name):
        called = {c for c in re.findall(r"\b(\w+)\s*\(", funcs[name]) if c in local}
        if called:
            raise ValueError(f"{name} calls helper {sorted(called)[0]}")
    prelude = "\n".join(l for l in prelude.splitlines()
                        if not re.match(r'\s*#\s*include\s*"std_testcase\.h"', l)).strip()
    return prelude, funcs[bad[0]], funcs[good_name], good_name, bad[0]

LEAK = re.compile(r"bad|good|flaw|cwe", re.I)

def neutralize(text):
    def ren(m):
        w = m.group(0)
        for a, b in (("BAD", "ONE"), ("Bad", "One"), ("bad", "one"),
                     ("GOOD", "TWO"), ("Good", "Two"), ("good", "two")):
            w = w.replace(a, b)
        return w
    # identifiers only; literals are left untouched and caught by the leak scan
    parts = TOKENS.split(text)
    lits = TOKENS.findall(text)
    parts = [re.sub(r"\b[A-Za-z_]\w*\b", lambda m: ren(m) if LEAK.search(m.group(0)) else m.group(0), p)
             for p in parts]
    return "".join(p + (lits[i] if i < len(lits) else "") for i, p in enumerate(parts))

def tidy(body):
    lines = [l.rstrip() for l in body.splitlines()]
    return "\n".join(l for l in lines if l.strip())

# ---- support headers: Juliet std_testcase.h + static-only io.c helpers ----
std = open(os.path.join(sup_dir, "std_testcase.h")).read()
std = re.sub(r"^extern (const )?int \w+;.*$", "", std, flags=re.M)
std = std.replace('#include "std_testcase_io.h"', '#include "io_static.h"')
io = open(os.path.join(sup_dir, "io.c")).read()
io = io[:io.index("/* define a bunch of these as empty functions")]   # drop good1..bad9
io = io.replace('#include "std_testcase.h"', "")
# functions: static inline (gcc emits unused plain statics even at -O0, which would
# add the same ~20 helpers to every O0 binary but not O3 and confound that factor)
io = re.sub(r"^\s?(void|size_t|int)( \w+ ?\()", r"static inline \1\2", io, flags=re.M)
io = re.sub(r"^(const int|int) ", r"static \1 ", io, flags=re.M)
sup = os.path.join(out, "juliet_support")
with open(os.path.join(sup, "std_testcase.h"), "w") as f:
    f.write("/* Juliet C/C++ v1.3 testcasesupport/std_testcase.h, extern globals moved to io_static.h */\n" + std)
with open(os.path.join(sup, "io_static.h"), "w") as f:
    f.write("/* Juliet C/C++ v1.3 testcasesupport/io.c helpers, made static so only the ones a\n"
            " * target calls end up in its binary. good1()..bad9() dummies dropped. */\n"
            "#ifndef _IO_STATIC_H\n#define _IO_STATIC_H\n" + io + "\n#endif\n")

# ---- candidate pools ----
pools = {c: {} for c in CLASSES}
for folder in sorted(os.listdir(tc_dir)):
    key = folder.split("_")[0]
    if key not in CWES: continue
    cls = CWES[key][2]
    for dp, _, fs in os.walk(os.path.join(tc_dir, folder)):
        for fn in fs:
            if not fn.endswith("_01.c") or NONDET.search(fn): continue
            if key == "CWE134" and "_console_" not in fn: continue
            pools[cls].setdefault(key, []).append(os.path.join(dp, fn))
if not any(k.startswith("CWE787") for k in os.listdir(tc_dir)):
    print("note: this Juliet release has no CWE787 folder; CWE-787 contributes 0 testcases")

def interleave(lists):
    lists = [sorted(l) for l in lists]
    while any(lists):
        for l in lists:
            if l: yield l.pop(0)

queues = {c: interleave([pools[c][k] for k in sorted(pools[c])]) for c in CLASSES}

labels, manifest, skipped = [], [], {}
n = 0
active = list(CLASSES)
while active and (limit == 0 or n < limit):
    for cls in list(active):
        if limit and n >= limit: break
        while True:
            path = next(queues[cls], None)
            if path is None:
                active.remove(cls); break
            try:
                prelude, bad, good, gname, bname = convert(path)
            except ValueError as e:
                skipped[str(e).split(":")[0]] = skipped.get(str(e).split(":")[0], 0) + 1
                continue
            prelude, bad, good = neutralize(prelude), tidy(neutralize(bad)), tidy(neutralize(good))
            # scan only Juliet-derived text (our own scaffold says VARIANT_BAD)
            if LEAK.search(prelude + bad + good):
                skipped["answer-leaking text"] = skipped.get("answer-leaking text", 0) + 1
                continue
            n += 1
            prog = f"j{n:04d}"
            body = (f"{prelude}\n\n"
                    f"#ifdef VARIANT_BAD\nvoid run_case(void)\n{bad}\n"
                    f"#else\nvoid run_case(void)\n{good}\n#endif\n\n"
                    "int main(void)\n{\n    run_case();\n    return 0;\n}\n")
            with open(os.path.join(out, prog + ".c"), "w") as f:
                f.write(f"/* {prog}: generated by scripts/fetch_juliet.sh from Juliet C/C++ v1.3;\n"
                        " * origin in targets/juliet_manifest.csv. Build with -DVARIANT_BAD for the\n"
                        " * vulnerable version, otherwise the fixed version. */\n"
                        '#include "juliet_support/std_testcase.h"\n' + body)
            key = os.path.basename(path).split("_")[0]
            cwe, cwe_name, _ = CWES[key]
            labels.append({"program": prog, "cwe": cwe, "cwe_name": cwe_name, "class": cls})
            manifest.append({"program": prog, "cwe": cwe, "class": cls,
                             "juliet_file": os.path.relpath(path, jroot),
                             "bad_function": bname, "good_function": gname})
            break

with open(os.path.join(out, "labels.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["program", "cwe", "cwe_name", "class"], lineterminator="\n")
    w.writeheader(); w.writerows(labels)
with open(os.path.join(out, "juliet_manifest.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["program", "cwe", "class", "juliet_file", "bad_function", "good_function"],
                       lineterminator="\n")
    w.writeheader(); w.writerows(manifest)
with open(os.path.join(out, "juliet_source.txt"), "w") as f:
    f.write(f"Juliet C/C++ Test Suite v1.3 (NIST SAMATE)\nurl: {url}\nsha256: {sha}\n")

by = {c: sum(1 for l in labels if l["class"] == c) for c in CLASSES}
print(f"Wrote {n} targets to {out}  ({', '.join(f'{c}={by[c]}' for c in CLASSES)})")
print("Eligible pool: " + ", ".join(f"{c}={sum(len(v) for v in pools[c].values())}" for c in CLASSES))
if skipped:
    print("Skipped (not single-function / leaking): " + ", ".join(f"{k}={v}" for k, v in sorted(skipped.items())))
print(f"Labels: {os.path.join(out, 'labels.csv')}   Manifest: {os.path.join(out, 'juliet_manifest.csv')}")
PY
