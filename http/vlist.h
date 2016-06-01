#ifndef VLIST_H
#define VLIST_H

#include "common_utils.h"

#define T_LIST              vp
#define T_LIST_DATA         void * 
#define T_LIST_EQL          IS_EQL 
#define T_LIST_PASS_DATA    1
#include "list_tmpl.h"

#define vlist_t             list_vp_t
#define vlist_node_t        list_vp_node_t       
#define vlist_init          list_vp_init
#define vlist_find          list_vp_find
#define vlist_push_front    list_vp_push_front
#define vlist_push_back     list_vp_push_back
#define vlist_remove_head   list_vp_remove_head
#define vlist_remove_tail   list_vp_remove_tail
#define vlist_insert        list_vp_insert
#define vlist_traverse      list_vp_traverse 
#define vlist_first         list_vp_first
#define vlist_last          list_vp_last
#define vlist_prev          list_vp_prev
#define vlist_next          list_vp_next
#define vlist_end           list_vp_end

static __inline void *vlist_front(vlist_t *list)
{
    void *data;
    vlist_node_t *node;
    node = vlist_first(list);
    if (node != (void *)list)
    {
        data = node->data;
        return data;
    }
    else
    {
        return NULL;
    }
}

static __inline void *vlist_back(vlist_t *list)
{
    void *data;
    vlist_node_t *node;
    node = vlist_last(list);
    if (node != (void *)list)
    {
        data = node->data;
        return data;
    }
    else
    {
        return NULL;
    }
}

static __inline void *vlist_pop_front(vlist_t *list)
{
    void *data;
    vlist_node_t *node;
    node = vlist_remove_head(list);
    if (node != (void *)list)
    {
        data = node->data;
        free(node);
        return data;
    }
    else
    {
        return NULL;
    }
}

static __inline void *vlist_pop_back(vlist_t *list)
{
    void *data;
    vlist_node_t *node;
    node = vlist_remove_tail(list);
    if (node != (void *)list)
    {
        data = node->data;
        free(node);
        return data;
    }
    else
    {
        return NULL;
    }
}

static __inline void vlist_erase(vlist_t *list, void *data, void(*free_fn)(void *))
{
    vlist_node_t *node = vlist_find(list, data);
    if (node != vlist_end(list))
    {
        RemoveEntryList(&node->entry);
        if (node->data != NULL && free_fn != NULL)
        {
            free_fn(node->data);
        }
        free(node);
    }
}

static __inline void vlist_clear(vlist_t *list, void (*free_fn)(void *))
{
    vlist_node_t *node;
    void *data;
    for (node = vlist_remove_head(list);
        node != vlist_end(list);
        node = vlist_remove_head(list))
    {
        data = node->data;
        if (data != NULL && free_fn != NULL)
        {
            free_fn(data);
        }
        free(node);
    }
}

#endif
