#include "lstring.h"
#include <stdlib.h>

#ifndef __cplusplus
#define max(a,b)    (((a) > (b)) ? (a) : (b))
#define min(a,b)    (((a) < (b)) ? (a) : (b))
#endif  /* __cplusplus */

lstring *lstr_assign(lstring *lstr, unsigned char *data, int len)
{
    lstr->data = data;
    lstr->len = len;
    return lstr;
}

lstring *lstr_alloc(lstring *lstr, int len)
{
    lstr->data = malloc(len);
    lstr->len = 0;
    return lstr;
}

lstring *lstr_free(lstring *lstr)
{
    if (lstr->data != NULL)
    {
        free(lstr->data);
        lstr->data = NULL;
    }
    lstr->len = 0;
    return lstr;
}

lstring *lstrcpy(lstring *dest, lstring *src)
{
    memcpy(dest->data, src->data, src->len);
    dest->len = src->len;
    return dest;
}

lstring *lstrcat(lstring *dest, lstring *src)
{
    memcpy(dest->data + dest->len, src->data, src->len);
    dest->len += src->len;
    return dest;
}

size_t lstrlen(const lstring *lstr)
{
    return lstr->len;
}

int lstrncmp(const lstring *lstring1, const lstring *lstring2, size_t count)
{
    int i;
    size_t n;
    n = min(min(lstring1->len, lstring2->len), count);
    for (i = 0; i < (int)n; i++)
    {
        if (lstring1->data[i] > lstring2->data[i])
        {
            return 1;
        }
        else if (lstring1->data[i] < lstring2->data[i])
        {
            return -1;
        }
        else
        {
            continue;
        }
    }

    if (n < count)
    {
        if (lstring1->len > lstring2->len)
        {
            return 1;
        }
        else if (lstring1->len < lstring2->len)
        {
            return -1;
        }
        else
        {
            return 0;
        }
    }
    else
    {
        return 0;
    }
}
