//#define T_LIST int
#ifdef T_LIST
#include "list_entry.h"
#include "bool_type.h"
#include <stdlib.h>
#include "tmpl_utils.h"

#ifdef HAVE_DEFAULT_LIST
#ifndef T_LIST_DATA
#define T_LIST_DATA void *
#endif

#ifndef T_LIST_EQL
#define T_LIST_EQL(x, y) x == y
#endif
#endif

#if T_LIST_PASS_DATA == PASS_BY_VALUE
#define T_CONST_IF
#define T_PTR_IF
#define T_ADDR_IF(x) x
#elif T_LIST_PASS_DATA == PASS_BY_POINTER
#define T_CONST_IF const
#define T_PTR_IF *
#define T_ADDR_IF(x) &x
#else
#endif

#define list_t              SAFE_CAT_NAME3(list, T_LIST, t)
#define list_node_t         SAFE_CAT_NAME3(list, T_LIST, node_t)
#define list_cmp            SAFE_CAT_NAME3(list, T_LIST, cmp)
#define list_init           SAFE_CAT_NAME3(list, T_LIST, init)
#define list_find           SAFE_CAT_NAME3(list, T_LIST, find)
#define list_push_front     SAFE_CAT_NAME3(list, T_LIST, push_front)
#define list_push_back      SAFE_CAT_NAME3(list, T_LIST, push_back)
#define list_remove_head    SAFE_CAT_NAME3(list, T_LIST, remove_head)
#define list_remove_tail    SAFE_CAT_NAME3(list, T_LIST, remove_tail)
#define list_insert         SAFE_CAT_NAME3(list, T_LIST, insert)
#define list_erase          SAFE_CAT_NAME3(list, T_LIST, erase)
#define list_clear          SAFE_CAT_NAME3(list, T_LIST, clear)
#define list_traverse       SAFE_CAT_NAME3(list, T_LIST, traverse)
#define list_first          SAFE_CAT_NAME3(list, T_LIST, first)
#define list_last           SAFE_CAT_NAME3(list, T_LIST, last)
#define list_prev           SAFE_CAT_NAME3(list, T_LIST, prev)
#define list_next           SAFE_CAT_NAME3(list, T_LIST, next)
#define list_end            SAFE_CAT_NAME3(list, T_LIST, end)

typedef struct
{
    LIST_ENTRY entry;
    T_LIST_DATA data;
} list_node_t;

typedef LIST_ENTRY list_t;

#ifndef DEFINE_LIST_TRAVERSE_CALLBACK
#define DEFINE_LIST_TRAVERSE_CALLBACK
typedef BOOL(*list_traverse_callback_t)(LIST_ENTRY *list, void *indata, void *outdata);
#endif

static __inline list_node_t *list_find(list_t *list, T_CONST_IF T_LIST_DATA T_PTR_IF data)
{
    list_node_t *node = (list_node_t *)list->Flink;
    while (node != (void *)list)
    {
        if (T_LIST_EQL(T_ADDR_IF(node->data), data))
        {
            break;
        }
        node = (list_node_t *)node->entry.Flink;
    }

    return (void *)node;
}

static __inline void list_push_front(list_t *list, T_CONST_IF T_LIST_DATA T_PTR_IF data)
{
    list_node_t *node = (list_node_t*)malloc(sizeof(list_node_t));
    if (node != NULL)
    {
        node->data = T_PTR_IF data;
        InsertHeadList(list, &node->entry);
    }
}

static __inline void list_push_back(list_t *list, T_LIST_DATA T_PTR_IF data)
{
    list_node_t *node = (list_node_t*)malloc(sizeof(list_node_t));
    if (node != NULL)
    {
        node->data = T_PTR_IF data;
        InsertTailList(list, &node->entry);
    }
}

static __inline void list_insert(list_t *list, T_LIST_DATA T_PTR_IF data)
{
    list_node_t *node = list_find(list, data);
    if (node == (void *)list)
    {
        list_push_back(list, data);
    }
}

static __inline void list_erase(list_t *list, T_LIST_DATA T_PTR_IF data)
{
    list_node_t *node = list_find(list, data);
    if (node != (void *)list)
    {
        RemoveEntryList(&node->entry);
        free(node);
    }
}

static __inline void list_init(list_t *list)
{
    InitializeListHead(list);
}

static __inline list_node_t *list_remove_head(list_t *list)
{
    return (list_node_t *)RemoveHeadList(list);
}

static __inline list_node_t *list_remove_tail(list_t *list)
{
    return (list_node_t *)RemoveTailList(list);
}

static __inline void list_traverse(list_t *list, 
    list_traverse_callback_t func, 
    void *indata, 
    void *outdata)
{
    LIST_ENTRY *entry = NULL;

    entry = (LIST_ENTRY *)list->Flink;
    while (entry != (void *)list)
    {
        if (FALSE == func(entry, indata, outdata))
        {
            break;
        }
        entry = entry->Flink;
    }
}

static __inline void list_clear(list_t *list)
{
    LIST_ENTRY *node = RemoveHeadList(list);
    while (node != (LIST_ENTRY *)list)
    {
        free(node);
        node = RemoveHeadList(list);
    }
}

static __inline list_node_t *list_first(list_t *list)
{
    return (list_node_t *)list->Flink;
}

static __inline list_node_t *list_last(list_t *list)
{
    return (list_node_t *)list->Blink;
}

static __inline list_node_t *list_prev(list_node_t *node)
{
    return  (list_node_t *)node->entry.Blink;
}

static __inline list_node_t *list_next(list_node_t *node)
{
    return  (list_node_t *)node->entry.Flink;
}

static __inline list_node_t *list_end(list_t *list)
{
    return (list_node_t *)list;
}

#undef T_LIST_USE_POINTER_DATA_PARAM
#undef T_LIST_EQL
#undef T_DATA_TERM

#undef T_PTR_IF
#undef T_ADDR_IF
#undef T_CONST_IF

#undef T_LIST_EQL
#undef T_LIST_PASS_DATA
#undef T_LIST_DATA
#undef T_LIST

#endif
