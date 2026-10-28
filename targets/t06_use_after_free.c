/* t06: CWE-416 Use After Free
 * Renamed from Juliet use-after-free pattern. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct node { char name[24]; int id; };

static void handle(const char *src)
{
    struct node *p = (struct node *)malloc(sizeof(struct node));
    if (!p) return;
    strncpy(p->name, src, sizeof(p->name) - 1);
    p->name[sizeof(p->name) - 1] = '\0';
    p->id = 1;
    free(p);
#ifdef VARIANT_BAD
    /* dereference after free */
    printf("%s %d\n", p->name, p->id);
#else
    printf("freed node\n");
#endif
}

int main(int argc, char **argv)
{
    handle(argc > 1 ? argv[1] : "obj");
    return 0;
}
