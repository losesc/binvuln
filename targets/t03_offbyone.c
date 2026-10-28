/* t03: CWE-193 / CWE-787 Off-by-one loop write past array end
 * Renamed from Juliet off-by-one pattern. */
#include <stdio.h>
#include <string.h>

static void fill_buffer(const char *src)
{
    char data[10];
    size_t len = strlen(src);
#ifdef VARIANT_BAD
    /* <= writes one element past the end when len == 10 */
    for (size_t i = 0; i <= len && i <= sizeof(data); i++)
        data[i] = src[i] ? src[i] : 'X';
#else
    for (size_t i = 0; i < len && i < sizeof(data); i++)
        data[i] = src[i];
#endif
    fwrite(data, 1, sizeof(data), stdout);
    putchar('\n');
}

int main(int argc, char **argv)
{
    fill_buffer(argc > 1 ? argv[1] : "0123456789");
    return 0;
}
