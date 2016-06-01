#ifdef T_BASIC
#include "tmpl_utils.h"

#define cmp_T SAFE_CAT_NAME2(cmp, T_BASIC)

static __inline int cmp_T(T_BASIC a, T_BASIC b)
{
    if(a > b)
    {
        return 1;
    }
    else if(a < b)
    {
        return -1;
    }
    else
    {
        return 0;
    }
}

#undef T_BASIC
#endif
