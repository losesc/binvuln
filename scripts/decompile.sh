set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BUILD="$ROOT/build"
SRC="$ROOT/targets"
OUT="$ROOT/decompiled"
SRCOUT="$ROOT/decompiled/source"
mkdir -p "$OUT" "$SRCOUT"

for c in "$SRC"/*.c; do
    prog="$(basename "$c" .c)"
    for variant in bad good; do
        def=""; [ "$variant" = bad ] && def="-DVARIANT_BAD"

        grep -vE '^\s*#\s*include' "$c" \
          | gcc -E -P $def -x c - 2>/dev/null \
          > "$SRCOUT/${prog}__${variant}.c.txt"
    done
done
echo "Source corpus: $(ls "$SRCOUT" | wc -l) files in $SRCOUT"

# ---- binary corpus ----
engine="objdump"
if [ -n "${GHIDRA_HOME:-}" ] && [ -x "$GHIDRA_HOME/support/analyzeHeadless" ]; then
    engine="ghidra"
fi
echo "Binary decompiler engine: $engine"

decompile_ghidra () {
    local bin="$1" out="$2"
    local proj; proj="$(mktemp -d)"
    # GhidraDecompile.java is a small headless script (see scripts/ghidra/)
    "$GHIDRA_HOME/support/analyzeHeadless" "$proj" tmpproj \
        -import "$bin" -scriptPath "$HERE/ghidra" \
        -postScript GhidraDecompile.java "$out" \
        -deleteProject >/dev/null 2>&1
    rm -rf "$proj"
    [ -s "$out" ]
}

decompile_objdump () {
    local bin="$1" out="$2"

    {
        # no file name here: it encodes program, bad/good variant and condition
        echo "; .text disassembly"
        objdump -d -M intel --no-show-raw-insn -j .text "$bin" \
          | sed -n '/Disassembly of section .text:/,$p' \
          | tail -n +3
    } > "$out"
    [ -s "$out" ]
}

count=0
for bin in "$BUILD"/*__*__O0 "$BUILD"/*__*__O0_s "$BUILD"/*__*__O3 "$BUILD"/*__*__O3_s; do
    [ -f "$bin" ] || continue
    name="$(basename "$bin")"
    out="$OUT/${name}.txt"
    if [ "$engine" = ghidra ]; then
        decompile_ghidra "$bin" "$out" || decompile_objdump "$bin" "$out"
    else
        decompile_objdump "$bin" "$out"
    fi
    count=$((count+1))
done
echo "Binary corpus: $count files in $OUT"
