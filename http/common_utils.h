#ifndef COMMON_UTILS_H
#define COMMON_UTILS_H

#ifndef __cplusplus
#ifndef max
#define max(a,b)    (((a) > (b)) ? (a) : (b))
#endif
#ifndef min
#define min(a,b)    (((a) < (b)) ? (a) : (b))
#endif
#endif  /* __cplusplus */

#define T_BASIC int
#include "basic_tmpl.h"
#include <ctype.h>

#define FAST_CSTRLEN(x) sizeof(x)-1

static int cmp_vp(void *p, void *q)
{
    if ((char *)p > (char *)q)
    {
        return 1;
    }
    else if ((char *)p < (char *)q)
    {
        return -1;
    }
    else
    {
        return 0;
    }
}

static __inline int xvalue(char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    else if (c >= 'a' && c <= 'f')
    {
        return c - 'a' + 10;
    }
    else if (c >= 'A' && c <= 'F')
    {
        return c - 'A' + 10;
    }
    else
    {
        return 0;
    }
}

static __inline const char *parse_hex_byte(unsigned char *dest, const char *src)
{
    int off = 0;
    int v = 0;
    for (; *src != '\0'; src++)
    {
        if (isxdigit(*src))
        {
            v = v * 16 + xvalue(*src);
            off++;
            if (off >= 2)
            {
                src++;
                break;
            }
        }
    }
    *dest = v;
    return src;
}

static __inline int parse_hex_string(unsigned char *dest, const char *src)
{
    int off;
    const char *p;
    off = 0;
    p = src;
    while (*p != '\0')
    {
        p = parse_hex_byte(dest+off, p);
        off++;
    }

    return off;
}

#define is_vp_equal(x, y) (char *)x == (char *)y
#define IS_EQL(x, y) x == y

#endif
