#ifndef YARA_UTILS_H
#define YARA_UTILS_H

extern "C"
{
    #include "yara.h"
}

#include "../http/http_template.h"

#define FILTER_PASS 0
#define FILTER_DROP 1

typedef struct
{
    YR_RULES *rules;
    pthread_mutex_t mutex;
} lock_rules_t;

typedef struct
{
    void *from;
    void *to;
    void *(*send_cb)(void *socket, unsigned char *buf, int len);
} HANDLER_USER_CONTEXT;

YR_RULES *parse_rule_file(const char *filename);
int lock_filter_data(lock_rules_t *rules, unsigned char *data, int length, HANDLER_USER_CONTEXT *context);

int test_filter();

#endif
