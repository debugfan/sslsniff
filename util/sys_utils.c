#include "sys_utils.h"

#define DEFAULT_PATH_DELIMITER  '/'

int multi_mkdir(const char *filepath, mode_t mode)
{
    char tmp[MAX_PATH];
    int off;

    for (off = 0; filepath[off] != '\0'; off++)
    {
        if (filepath[off] == DEFAULT_PATH_DELIMITER)
        {
            tmp[off] = DEFAULT_PATH_DELIMITER;
            tmp[off + 1] = '\0';

            if (off > 0 && 0 != access(tmp, 0))
            {
                if (0 != mkdir(tmp, mode))
                {
                    return -1;
                }
            }
        }
        else
        {
            tmp[off] = filepath[off];
        }
    }

    tmp[off] = '\0';
    if (off > 0 && 0 != access(tmp, 0))
    {
        if (0 != mkdir(tmp, mode))
        {
            return -1;
        }
    }

    return 0;
}
