/* t05: CWE-134 Uncontrolled Format String via fprintf
 * Renamed from Juliet format string (fprintf) pattern. */
#include <stdio.h>
#include <string.h>

static void record_event(const char *tag)
{
    char msg[64];
    snprintf(msg, sizeof(msg), "event:%s", tag);
#ifdef VARIANT_BAD
    fprintf(stderr, msg);
    fputc('\n', stderr);
#else
    fprintf(stderr, "%s\n", msg);
#endif
}

int main(int argc, char **argv)
{
    record_event(argc > 1 ? argv[1] : "startup");
    return 0;
}
