/* t04: CWE-134 Uncontrolled Format String
 * Renamed from Juliet format string pattern. */
#include <stdio.h>
#include <string.h>

static void emit(const char *src)
{
    char line[128];
    strncpy(line, src, sizeof(line) - 1);
    line[sizeof(line) - 1] = '\0';
#ifdef VARIANT_BAD
    /* user input used as the format string */
    printf(line);
    putchar('\n');
#else
    printf("%s\n", line);
#endif
}

int main(int argc, char **argv)
{
    emit(argc > 1 ? argv[1] : "hello");
    return 0;
}
