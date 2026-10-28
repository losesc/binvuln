/* t02: CWE-787 / CWE-121 Out-of-bounds Write via unchecked length
 * Renamed from Juliet memcpy overflow pattern. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void copy_into_fixed(const char *src, int n)
{
    char dest[16];
#ifdef VARIANT_BAD
    /* attacker-controlled n used directly */
    memcpy(dest, src, (size_t)n);
#else
    size_t safe = (size_t)n;
    if (safe > sizeof(dest)) safe = sizeof(dest);
    memcpy(dest, src, safe);
#endif
    for (size_t i = 0; i < sizeof(dest); i++) {
        if (dest[i] == 0) break;
        putchar(dest[i]);
    }
    putchar('\n');
}

int main(int argc, char **argv)
{
    const char *payload = (argc > 1) ? argv[1] : "AAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    int n = (int)strlen(payload);
    copy_into_fixed(payload, n);
    return 0;
}
