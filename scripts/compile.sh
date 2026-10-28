set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
SRC="$ROOT/targets"
OUT="$ROOT/build"
CC="${CC:-gcc}"

COMMON_FLAGS="-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -fno-stack-protector -no-pie -fno-pic -w"

mkdir -p "$OUT"
rm -f "$OUT"/*.bin "$OUT"/* 2>/dev/null || true
: > "$OUT/build_matrix.csv"
echo "program,variant,opt,symbols,binary" >> "$OUT/build_matrix.csv"

build_one () {
    local src="$1" prog="$2" variant="$3" def="$4"
    for opt in O0 O3; do
        local base="${prog}__${variant}__${opt}"
        local kept="$OUT/${base}"
        # compile with debug symbols kept
        $CC -${opt} -g $def $COMMON_FLAGS -o "$kept" "$src"
        echo "${prog},${variant},${opt},kept,${base}" >> "$OUT/build_matrix.csv"
        # stripped = exact copy of the kept binary, symbols removed
        local strp="$OUT/${base}_s"
        cp "$kept" "$strp"
        strip --strip-all "$strp"
        echo "${prog},${variant},${opt},stripped,${base}_s" >> "$OUT/build_matrix.csv"
    done
}

shopt -s nullglob
for src in "$SRC"/*.c; do
    prog="$(basename "$src" .c)"
    build_one "$src" "$prog" "bad"  "-DVARIANT_BAD"
    build_one "$src" "$prog" "good" ""
done

echo
echo "Built $(($(wc -l < "$OUT/build_matrix.csv") - 1)) binaries into $OUT"
echo "Matrix: $OUT/build_matrix.csv"
