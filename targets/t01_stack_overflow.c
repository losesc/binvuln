/* t01: CWE-121 Stack-based Buffer Overflow
 * Derived from Juliet CWE121 strcpy pattern, identifiers renamed to remove leakage.
 * Build with -DVARIANT_BAD for the vulnerable version, otherwise the fixed version. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void process_record(const char *src)
{
    char local_store[32];
#ifdef VARIANT_BAD
    /* no bounds check: src may exceed local_store */
    strcpy(local_store, src);
#else
    /* fixed: bounded copy with explicit termination */
    strncpy(local_store, src, sizeof(local_store) - 1);
    local_store[sizeof(local_store) - 1] = '\0';
#endif
    printf("%s\n", local_store);
}

int main(int argc, char **argv)
{
    char buf[256];
    if (argc > 1) {
        strncpy(buf, argv[1], sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
    } else {
        if (!fgets(buf, sizeof(buf), stdin)) return 0;
    }
    process_record(buf);
    return 0;
}
