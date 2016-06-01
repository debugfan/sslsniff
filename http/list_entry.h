#ifndef LIST_ENTRY_H
#define LIST_ENTRY_H

/* Define NULL pointer value */
#ifndef NULL
#ifdef __cplusplus
#define NULL    0
#else  /* __cplusplus */
#define NULL    ((void *)0)
#endif  /* __cplusplus */
#endif  /* NULL */

typedef struct _LIST_ENTRY
{
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

/* list manipulation macros */
#define InitializeListHead(le)  (void)((le)->Flink = (le)->Blink = (le))
#define InsertHeadList(le,e)    do { PLIST_ENTRY f = (le)->Flink; (e)->Flink = f; (e)->Blink = (le); f->Blink = (e); (le)->Flink = (e); } while (0)
#define InsertTailList(le,e)    do { PLIST_ENTRY b = (le)->Blink; (e)->Flink = (le); (e)->Blink = b; b->Flink = (e); (le)->Blink = (e); } while (0)
#define IsListEmpty(le)         ((le)->Flink == (le))
#define RemoveEntryList(e)      do { PLIST_ENTRY f = (e)->Flink, b = (e)->Blink; f->Blink = b; b->Flink = f; (e)->Flink = (e)->Blink = NULL; } while (0)

static  __inline PLIST_ENTRY RemoveHeadList(PLIST_ENTRY le)
{
    PLIST_ENTRY f, b, e;

    e = le->Flink;
    f = le->Flink->Flink;
    b = le->Flink->Blink;
    f->Blink = b;
    b->Flink = f;

    if (e != le) e->Flink = e->Blink = NULL;
    return e;
}

static __inline PLIST_ENTRY RemoveTailList(PLIST_ENTRY le)
{
    PLIST_ENTRY f, b, e;

    e = le->Blink;
    f = le->Blink->Flink;
    b = le->Blink->Blink;
    f->Blink = b;
    b->Flink = f;

    if (e != le) e->Flink = e->Blink = NULL;
    return e;
}

#endif
