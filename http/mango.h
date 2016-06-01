#ifndef MANGO_H
#define MANGO_H

#include "ftrie.h"

typedef struct {
    ftrie_t dict;
    ftrie_t funcs;
} mango_context_t;

void mango_init(mango_context_t *ctx);
void mango_set_dictionary_pair(mango_context_t *ctx, const char *key, const char *value);
void mango_set_function(mango_context_t *ctx, const char *key, int(*func)(char *buf, int len));
int mango_parse(mango_context_t *ctx, char *dest, int dest_len, const char *src, int src_len);
void mango_finish(mango_context_t *ctx);

#endif
