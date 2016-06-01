#ifndef JSON_HELPER_H
#define JSON_HELPER_H

#include <stdio.h>
#include <pthread.h>

void json_write(FILE *fp,
    unsigned int session_id,
    const char *src_ip,
    int src_port,
    const char *dest_ip,
    int dest_port,
    const char *buf,
    int len);

extern FILE *json_fp;
extern pthread_mutex_t json_mutex;

#endif
