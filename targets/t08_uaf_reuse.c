/* t08: CWE-416 Use After Free via reused freed region
 * Renamed from Juliet use-after-free (reuse) pattern. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int parse_len(const char *s)
{
    int v = 0;
    for (; *s >= '0' && *s <= '9'; s++) v = v * 10 + (*s - '0');
    return v;
}

static void task(const char *src)
{
    char *region = (char *)malloc(64);
    if (!region) return;
    memset(region, 'A', 63);
    region[63] = '\0';
    free(region);
    int extra = parse_len(src);
#ifdef VARIANT_BAD
    /* write into region after it was freed */
    if (extra > 0 && extra < 64) region[extra] = 'Z';
    printf("%c\n", region[extra > 0 ? extra : 0]);
#else
    (void)extra;
    printf("released\n");
#endif
}

int main(int argc, char **argv)
{
    task(argc > 1 ? argv[1] : "5");
    return 0;
}
