#!/usr/bin/env python3
import argparse, csv, json, os, re, sys, time, urllib.request, urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DECOMP = os.path.join(ROOT, "decompiled")
SRCDIR = os.path.join(DECOMP, "source")
RESULTS = os.path.join(ROOT, "results")
LABELS = os.path.join(ROOT, "targets", "labels.csv")

SYSTEM_PROMPT = (
    "You are a security researcher, expert in detecting security vulnerabilities. "
    "Provide response only in following format: "
    "vulnerability: <YES or NO> | vulnerability type: <CWE ID> | "
    "vulnerability name: <CWE NAME> | explanation: <explanation for prediction>. "
    "Use N/A in other fields if there are no vulnerabilities. "
    "Do not include anything else in response."
)

def load_labels():
    m = {}
    with open(LABELS) as f:
        for row in csv.DictReader(f):
            m[row["program"]] = row
    return m

def user_prompt(mode, cwe, code):
    if mode == "basic":
        head = "Is the following code snippet prone to any security vulnerability?"
    else:  # cwe-specific
        head = f"Is the following code snippet prone to {cwe}?"
    return f"{head}\n{code}\nResponse:"

def call_ollama(model, system, user, host):
    body = json.dumps({
        "model": model,
        "stream": False,
        "options": {"temperature": 0, "num_predict": 1024},
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }).encode()
    req = urllib.request.Request(f"{host}/api/chat", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.loads(r.read())["message"]["content"]

VULN_RE = re.compile(r"vulnerability\s*:\s*(YES|NO)", re.I)
TYPE_RE = re.compile(r"vulnerability type\s*:\s*(CWE[-\s]?\d+|N/?A)", re.I)

def parse_verdict(text):
    v = VULN_RE.search(text or "")
    t = TYPE_RE.search(text or "")
    pred_vuln = (v.group(1).upper() == "YES") if v else None
    pred_cwe = None
    if t:
        raw = t.group(1).upper().replace(" ", "").replace("CWE", "CWE-").replace("CWE--", "CWE-")
        pred_cwe = None if raw.startswith("N") else raw
    return pred_vuln, pred_cwe, text

def fake_verdict(program, variant, condition, true_cwe):
    """Deterministic stand-in so the pipeline/scorer can be tested without a GPU.
    Mimics the paper's pattern: high recall, precision ~0.5, degrading when stripped/O3."""
    import hashlib
    h = int(hashlib.md5(f"{program}{variant}{condition}".encode()).hexdigest(), 16)
    # bad variant: almost always flagged (high recall). good: flagged ~half the time.
    if variant == "bad":
        pred_vuln = (h % 100) > (5 if "O0" in condition and "kept" not in condition else 10)
    else:
        noisy = 60 if ("O3" in condition or "stripped" in condition) else 45
        pred_vuln = (h % 100) < noisy
    # CWE correctness drops as the condition gets harder
    hard = ("O3" in condition) + ("stripped" in condition)
    cwe_ok = (h % 10) >= (2 + 3 * hard)
    pred_cwe = true_cwe if (pred_vuln and cwe_ok) else ("CWE-787" if pred_vuln else None)
    return pred_vuln, pred_cwe, f"[dry-run] vulnerability: {'YES' if pred_vuln else 'NO'} | vulnerability type: {pred_cwe or 'N/A'}"

def iter_items(labels):
    """Yield (program, variant, condition, path) for source + 4 binary builds."""
    # source condition
    for program in labels:
        for variant in ("bad", "good"):
            p = os.path.join(SRCDIR, f"{program}__{variant}.c.txt")
            if os.path.exists(p):
                yield program, variant, "source", p
    # binary conditions
    cond = {"O0": "O0", "O0_s": "O0", "O3": "O3", "O3_s": "O3"}
    sym = {"O0": "kept", "O0_s": "stripped", "O3": "kept", "O3_s": "stripped"}
    for program in labels:
        for variant in ("bad", "good"):
            for suf in ("O0", "O0_s", "O3", "O3_s"):
                p = os.path.join(DECOMP, f"{program}__{variant}__{suf}.txt")
                if os.path.exists(p):
                    yield program, variant, f"{cond[suf]}/{sym[suf]}", p

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="qwen2.5-coder:14b")
    ap.add_argument("--prompt", choices=["basic", "cwe"], default="cwe")
    ap.add_argument("--host", default=os.environ.get("OLLAMA_HOST", "http://localhost:11434"))
    ap.add_argument("--dry-run", action="store_true", help="no Ollama; deterministic fake verdicts for testing")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    labels = load_labels()
    os.makedirs(RESULTS, exist_ok=True)
    out = args.out or os.path.join(RESULTS, f"runs_{args.model.replace(':','_').replace('/','_')}_{args.prompt}.jsonl")

    n = 0
    with open(out, "w") as fout:
        for program, variant, condition, path in iter_items(labels):
            true_cwe = labels[program]["cwe"]
            true_vuln = (variant == "bad")
            with open(path, errors="ignore") as f:
                code = f.read()
            cwe_for_prompt = f'{true_cwe} ({labels[program]["cwe_name"]})'
            up = user_prompt(args.prompt, cwe_for_prompt, code)
            t0 = time.time()
            if args.dry_run:
                pv, pc, raw = fake_verdict(program, variant, condition, true_cwe)
                err = None
            else:
                try:
                    raw = call_ollama(args.model, SYSTEM_PROMPT, up, args.host)
                    pv, pc, raw = parse_verdict(raw)
                    err = None
                except (urllib.error.URLError, OSError, KeyError, ValueError) as e:
                    pv = pc = raw = None
                    err = str(e)
            row = {
                "program": program, "variant": variant, "condition": condition,
                "true_vuln": true_vuln, "true_cwe": true_cwe,
                "pred_vuln": pv, "pred_cwe": pc,
                "latency_s": round(time.time() - t0, 2),
                "model": args.model, "prompt": args.prompt,
                "raw": (raw or "")[:800], "error": err,
            }
            fout.write(json.dumps(row) + "\n")
            fout.flush()
            n += 1
            tag = "DRY" if args.dry_run else ("ERR" if err else "ok")
            print(f"[{tag}] {program:22s} {variant:4s} {condition:12s} "
                  f"pred_vuln={pv} pred_cwe={pc}", file=sys.stderr)
    print(f"\nWrote {n} rows -> {out}")

if __name__ == "__main__":
    main()
