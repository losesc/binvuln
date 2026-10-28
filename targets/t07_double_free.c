/* t07: CWE-415 / CWE-416 Double Free
 * Renamed from Juliet double-free pattern. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void run(const char *src)
{
    char *b = (char *)malloc(32);
    if (!b) return;
    strncpy(b, src, 31);
    b[31] = '\0';
    free(b);
#ifdef VARIANT_BAD
    /* second free of the same pointer */
    free(b);
#else
    b = NULL;
#endif
    printf("done\n");
}

int main(int argc, char **argv)
{
    run(argc > 1 ? argv[1] : "data");
    return 0;
}
