#ifndef SYS_UTILS_H
#define SYS_UTILS_H

#include <sys/stat.h>
#include <sys/types.h>

#ifndef MAX_PATH
#define MAX_PATH    260
#endif

#ifdef __cplusplus
extern "C"
{
#endif

int multi_mkdir(const char *filepath, mode_t mode);

#ifdef __cplusplus
}
#endif 

#endif
