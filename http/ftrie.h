#ifndef FTRIE_H
#define FTRIE_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "bool_type.h"
#include "vlist.h"

#ifdef __cplusplus
}
#endif

#ifndef TRIE_ALPHABET_SIZE
#define TRIE_ALPHABET_SIZE 128
#endif

// trie node
typedef struct _ftrie_node
{
    int state;
    void *data;
    struct _ftrie_node *children[TRIE_ALPHABET_SIZE];
} ftrie_node_t;

typedef ftrie_node_t ftrie_t;

void ftrie_init(ftrie_t *trie);
void ftrie_insert(ftrie_t *trie, const char *word, int word_len, void *data);
void *ftrie_get(ftrie_t *trie, const char *word, int word_len);
void ftrie_clear(ftrie_t *trie);
BOOL ftrie_exist(ftrie_t *trie, const char word[], int word_len);
void ftrie_get_all(ftrie_t *trie, const char word[], int word_len, int partial, vlist_t *list);

#endif
