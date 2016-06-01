#ifndef SSLSNIFF_GLOBAL_H
#define SSLSNIFF_GLOBAL_H

#include <string>

#include "util/yara_utils.h"

typedef struct
{
    lock_rules_t client_rules;
    lock_rules_t server_rules;
    std::string log_file;
    std::string json_file;
    std::string pcap_file;
} ssl_global_t;

extern ssl_global_t g_vars;

#endif

