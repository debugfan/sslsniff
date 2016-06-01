#include "ftrie.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void ftrie_init(ftrie_t *trie)
{
    memset(trie, 0, sizeof(ftrie_t));
}

void ftrie_insert(ftrie_t *trie, const char word[], int word_len, void *data)
{
    int c;
    int off;
    ftrie_node_t *t = trie;
    ftrie_node_t *tmp;

    if (word_len > 0)
    {
        off = 0;
    }
    
    //while ((c = *word++))
    while (1)
    {
        if (word_len == 0)
        {
            c = *word++;
            if (!c)
            {
                break;
            }
        }
        else
        {
            if (off >= word_len)
            {
                break;
            }
            c = word[off++];
        }

        if (t->children[c] == NULL)
        {
            tmp = malloc(sizeof(ftrie_node_t));
            if (tmp != NULL)
            {
                memset(tmp, 0, sizeof(ftrie_node_t));
            }

            t->children[c] = tmp;
        }

        t = t->children[c];
    }

    t->state = 1;
    t->data = data;
}

ftrie_node_t *ftrie_search(ftrie_t *trie, const char word[], int word_len)
{
    int c;
    int off;
    ftrie_node_t *t = trie;

    if (word_len > 0)
    {
        off = 0;
    }

    //while ((c = *word++))
    while (1)
    {
        if (word_len == 0)
        {
            c = *word++;
            if (!c)
            {
                break;
            }
        }
        else
        {
            if (off >= word_len)
            {
                break;
            }
            c = word[off++];
        }

        if (t->children[c] == NULL) 
        {
            return NULL;
        }
        t = t->children[c];
    }
    return t;
}

void ftrie_clear(ftrie_t *trie)
{
    int i;
    ftrie_node_t *t = trie;
    for (i = 0; i < TRIE_ALPHABET_SIZE; i++)
    {
        if (t->children[i] != NULL)
        {
            ftrie_clear(t->children[i]);
            free(t->children[i]);
            t->children[i] = NULL;
        }
    }
}

void ftrie_get_all(ftrie_t *trie, const char word[], int word_len, int partial, vlist_t *list)
{
    int c;
    int off;
    ftrie_node_t *t = trie;

    if (word_len > 0)
    {
        off = 0;
    }

    while (1)
    {
        if (word_len == 0)
        {
            c = *word++;
            if (!c)
            {
                break;
            }
        }
        else
        {
            if (off >= word_len)
            {
                break;
            }
            c = word[off++];
        }

        if (t->state == 1 && partial != 0)
        {
            vlist_insert(list, t->data);
        }

        if (t->children[c] == NULL)
        {
            return;
        }

        t = t->children[c];
    }

    if (t->state == 1)
    {
        vlist_insert(list, t->data);
    }
}

void *ftrie_get(ftrie_t *trie, const char *word, int word_len)
{
    ftrie_node_t *t = ftrie_search(trie, word, word_len);
    if (t != NULL && t->state == 1)
    {
        return t->data;
    }
    else
    {
        return NULL;
    }
}

BOOL ftrie_exist(ftrie_t *trie, const char word[], int word_len)
{
    ftrie_node_t *t = ftrie_search(trie, word, word_len);
    if (t != NULL && t->state == 1)
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}
