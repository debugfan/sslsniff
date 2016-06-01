#ifndef LSTRING_H
#define LSTRING_H

#include <string.h>

typedef struct tag_lstring {
    size_t len;
    unsigned char * data;
} lstring;

lstring *lstr_alloc(lstring *lstr, int len);
lstring *lstr_free(lstring *lstr);
lstring *lstr_assign(lstring *lstr, unsigned char *data, int len);

lstring *lstrcpy(lstring *dest, lstring *src);
lstring *lstrcat(lstring *dest, lstring *src);
size_t lstrlen(const lstring *lstr);
int lstrncmp(const lstring *lstring1, const lstring *lstring2, size_t count);

#endif
