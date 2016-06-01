#ifndef TMPL_UTILS_H
#define TMPL_UTILS_H

#define CAT_NAME2(x, y) x##_##y
#define SAFE_CAT_NAME2(x, y) CAT_NAME2(x, y)

#define CAT_NAME3(x, y, z) x##_##y##_##z
#define SAFE_CAT_NAME3(x, y, z) CAT_NAME3(x, y, z)

#define PASS_BY_VALUE         1
#define PASS_BY_POINTER       2
#define PASS_BY_REFER         3

#endif
