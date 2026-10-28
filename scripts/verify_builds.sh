set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
SRC="$ROOT/targets"
OUT="$ROOT/build"
CC="${CC:-gcc}"
ASAN_DIR="$ROOT/build/asan"
mkdir -p "$ASAN_DIR"

echo "=== Check 1: stripped vs kept code section identical ==="
code_identical_fail=0
for kept in "$OUT"/*__*__O0 "$OUT"/*__*__O3; do
    [ -f "$kept" ] || continue
    strp="${kept}_s"
    [ -f "$strp" ] || continue

    objcopy -O binary --only-section=.text "$kept" /tmp/_vb_a.text 2>/dev/null
    objcopy -O binary --only-section=.text "$strp" /tmp/_vb_b.text 2>/dev/null
    if cmp -s /tmp/_vb_a.text /tmp/_vb_b.text; then
        echo "  OK   $(basename "$kept")  ==  $(basename "$strp")"
    else
        echo "  DIFF $(basename "$kept")  !=  $(basename "$strp")"
        code_identical_fail=1
    fi
done

echo
echo "=== Check 2: bug survives compilation (ASan) ==="
echo "program,opt,class,evidence,confirmed" > "$ROOT/build/bug_survives.csv"

classify () {
    local cls; cls="$(awk -F, -v p="$1" 'NR > 1 && $1 == p { print $NF }' "$SRC/labels.csv")"
    [ "$cls" = format_string ] && echo format_string || echo memory
}

for src in "$SRC"/*.c; do
    prog="$(basename "$src" .c)"
    cls="$(classify "$prog")"
    for opt in O0 O3; do
        bin="$ASAN_DIR/${prog}__bad__${opt}_asan"
        $CC -${opt} -g -fsanitize=address -U_FORTIFY_SOURCE -fno-stack-protector \
            -DVARIANT_BAD -w -o "$bin" "$src" 2>/dev/null || { echo "  build-fail $prog $opt"; continue; }
        if [ "$cls" = "format_string" ]; then

            payload='%x.%x.%x.%x.%s.%s.%n'
            out="$(printf '%s\n' "$payload" | ASAN_OPTIONS=detect_leaks=0 "$bin" "$payload" 2>&1; echo "rc=$?")"
            rc="${out##*rc=}"
            if echo "$out" | grep -q "AddressSanitizer\|ERROR:\|SEGV\|Segmentation" || [ "$rc" -ge 128 ]; then
                ev="crash-on-format-specifier"; conf=yes
            else
                ev="no-crash"; conf=no
            fi
        else
            payload="$(printf 'A%.0s' {1..200})"
            out="$(printf '%s\n' "$payload" | ASAN_OPTIONS=detect_leaks=0 "$bin" "$payload" 2>&1 || true)"
            if echo "$out" | grep -q "AddressSanitizer\|ERROR: "; then
                ev="asan-report"; conf=yes
            else
                ev="asan-silent"; conf=no
            fi
        fi
        [ "$conf" = yes ] && echo "  CONFIRMED $prog $opt ($cls, $ev)" \
                          || echo "  UNCONFIRMED $prog $opt ($cls, $ev) -- flag this target"
        echo "${prog},${opt},${cls},${ev},${conf}" >> "$ROOT/build/bug_survives.csv"
    done
done

echo
[ "$code_identical_fail" -eq 0 ] && echo "Check 1 passed: all stripped twins share code with their kept binary." \
                                 || echo "Check 1 WARNING: some stripped twins differ — investigate before scoring."
echo "Check 2 results: $ROOT/build/bug_survives.csv"
