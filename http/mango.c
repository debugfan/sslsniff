#include "mango.h"
#include <stdlib.h>
#include <string.h>

#define CONST_STRLEN(x) sizeof(x) - 1 

#ifdef WIN32
char *
strnstr(s, find, slen)
const char *s;
const char *find;
size_t slen;
{
    char c, sc;
    size_t len;

    if ((c = *find++) != '\0') {
        len = strlen(find);
        do {
            do {
                if ((sc = *s++) == '\0' || slen-- < 1)
                    return (NULL);
            } while (sc != c);
            if (len > slen)
                return (NULL);
        } while (strncmp(s, find, len) != 0);
        s--;
    }
    return ((char *)s);
}
#endif

void mango_init(mango_context_t *ctx)
{
    ftrie_init(&ctx->dict);
    ftrie_init(&ctx->funcs);
}

void mango_set_dictionary_pair(mango_context_t *ctx, const char *key, const char *value)
{
    ftrie_insert(&ctx->dict, key, 0, (void *)value);
}

void mango_set_function(mango_context_t *ctx, const char *key, int (*func)(char *buf, int len))
{
    ftrie_insert(&ctx->funcs, key, 0, (void *)func);
}

int nstrcpy(char *s1, const char *s2)
{
    char *s = s1;
    for (s = s1; (*s = *s2) != 0; s++, s2++);
    return (s - s1);
}

int nmemcpy(void *dest, void *src, int len)
{
    memcpy(dest, src, len);
    return len;
}

int mango_parse_as_comment(mango_context_t *ctx, char *dest, int dest_len, const char *src, int src_len, int *parsed)
{
    int written;
    char *end;
    end = strnstr(src, "#}", src_len);
    if (end != NULL)
    {
        *parsed = end + CONST_STRLEN("#}") - src;
        written = 0;
    }
    else
    {
        memcpy(dest, "{#", CONST_STRLEN("{#"));
        memcpy(dest + CONST_STRLEN("{#"), src, src_len);
        *parsed = src_len;
        written = CONST_STRLEN("{#") + src_len;
    }

    return written;
}

int mango_parse_as_string(mango_context_t *ctx, char *dest, int dest_len, const char *src, int src_len, int *parsed)
{
    int written;
    const char *start;
    const char *end;
    int nload;
    start = src + 1;
    end = strnstr(start, "\"}}", src_len - 1);
    if (end != NULL)
    {
        nload = end - start;
        if (nload > 0)
        {
            memcpy(dest, start, nload);
        }
        *parsed = end + CONST_STRLEN("\"}}") - src;
        written = nload;
    }
    else
    {
        memcpy(dest, "{{\"", CONST_STRLEN("{{\""));
        memcpy(dest + CONST_STRLEN("{{\""), src, src_len);
        *parsed = src_len;
        written = CONST_STRLEN("{{\"") + src_len;
    }

    return written;
}

int mango_parse_as_function(mango_context_t *ctx, char *dest, int dest_len, const char *src, int src_len, int *parsed)
{
    int written;
    const char *start;
    const char *end;
    int var_len;
    int (*func)(char *buf, int len);
    const char *final_pos;
    start = src + 1;
    end = strnstr(start, ")}}", src_len - 1);
    if (end != NULL)
    {
        var_len = end - start;
        if (var_len > 0)
        {
            func = ftrie_get(&ctx->funcs, start, var_len);
            if (func != NULL)
            {
                written = func(dest, dest_len);
                *parsed = end - src + CONST_STRLEN(")}}");
                return written;
            }
        }

        final_pos = end + CONST_STRLEN(")}}");
        memcpy(dest, "{{(", CONST_STRLEN("{{("));
        memcpy(dest + CONST_STRLEN("{{("), src, final_pos - src);
        *parsed = final_pos - src;
        written = CONST_STRLEN("{{(") + final_pos - src;
    }
    else
    {
        memcpy(dest, "{{(", CONST_STRLEN("{{("));
        memcpy(dest + CONST_STRLEN("{{("), src, src_len);
        *parsed = src_len;
        written = CONST_STRLEN("{{(") + src_len;
    }

    return written;
}

int mango_parse_as_variable(mango_context_t *ctx, char *dest, int dest_len, const char *src, int src_len, int *parsed)
{
    int written;
    char *end;
    int var_len;
    void *data;
    end = strnstr(src, "}}", src_len);
    if (end != NULL)
    {
        var_len = end - src;
        if (var_len > 0)
        {
            data = ftrie_get(&ctx->dict, src, var_len);
            if (data != NULL)
            {
                written = nstrcpy(dest, data);
                *parsed = var_len + CONST_STRLEN("}}");
                return written;
            }
        }
        
        memcpy(dest, "{{", 2);
        memcpy(dest + CONST_STRLEN("{{"), src, end + CONST_STRLEN("}}") - src);
        *parsed = end + CONST_STRLEN("}}") - src;
        written = CONST_STRLEN("{{") + end + CONST_STRLEN("}}") - src;
    }
    else
    {
        memcpy(dest, "{{", CONST_STRLEN("{{"));
        memcpy(dest + CONST_STRLEN("{{"), src, src_len);
        *parsed = src_len;
        written = CONST_STRLEN("{{") + src_len;
    }

    return written;
}

int mango_parse_as_expression(mango_context_t *ctx, char *dest, int dest_len, const char *src, int src_len, int *parsed)
{
    if (src_len > 0)
    {
        switch (src[0])
        {
        case '\"':
            return mango_parse_as_string(ctx, dest, dest_len, src, src_len, parsed);
            break;
        case '(':
            return mango_parse_as_function(ctx, dest, dest_len, src, src_len, parsed);
            break;
        default:
            return mango_parse_as_variable(ctx, dest, dest_len, src, src_len, parsed);
            break;
        }
    }
    else
    {
        return 0;
    }
}

int mango_parse(mango_context_t *ctx, char *dest, int dest_len, const char *src, int src_len)
{

#define MATCHED_NORMAL                  0
#define MATCHED_OPENING_BRACE           1
#define MATCHED_COMMENT                 2
#define MATCHED_EXPRESSION              3

    int si, di;
    const char *last_pos;
    int span;
    int bflush;
    int written;
    int parsed;
    int state;

    state = MATCHED_NORMAL;
    last_pos = src;
    bflush = 0;
    for (si = 0, di = 0; si < src_len && di < dest_len; si++)
    {
        switch (state)
        {
        case MATCHED_NORMAL:
            switch (src[si])
            {
            case '{':
                state = MATCHED_OPENING_BRACE;
                bflush = 1;
                break;
            default:
                break;
            }
            break;
        case MATCHED_OPENING_BRACE:
            switch (src[si])
            {
            case '#':
                state = MATCHED_COMMENT;
                break;
            case '{':
                state = MATCHED_EXPRESSION;
                break;
            default:
                bflush = 1;
                state = MATCHED_NORMAL;
                break;
            }
            break;
        case MATCHED_COMMENT:
            written = mango_parse_as_comment(ctx, dest + di, dest_len - di, src + si, src_len - si, &parsed);
            si += parsed;
            di += written;
            last_pos = src + si;
            state = MATCHED_NORMAL;
            break;
        case MATCHED_EXPRESSION:
            written = mango_parse_as_expression(ctx, dest + di, dest_len - di, src + si, src_len - si, &parsed);
            si += parsed;
            di += written;
            last_pos = src + si;
            state = MATCHED_NORMAL;
            break;
        }

        if (bflush != 0)
        {
            span = src + si - last_pos;
            if (span > 0)
            {
                memcpy(dest + di, last_pos, span);
                di += span;
                last_pos = src + si;
            }
            bflush = 0;
        }
    }

    span = src + si - last_pos;
    if (span > 0)
    {
        memcpy(dest + di, last_pos, span);
        di += span;
        last_pos = src + si;
    }

    dest[di] = '\0';
    return di;
}

void mango_finish(mango_context_t *ctx)
{
    ftrie_clear(&ctx->dict);
}
