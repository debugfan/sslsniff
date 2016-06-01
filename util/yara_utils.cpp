#include "yara_utils.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#ifndef PRIx64
#define PRIx64 "llx"
#endif

#define HANDLER_ACTION_NONE                 0
#define HANDLER_ACTION_DROP                 1
#define HANDLER_ACTION_REPLACE              2
#define HANDLER_ACTION_HEX_REPLACE          3
#define HANDLER_ACTION_HTTP_REPLACE         4
#define HANDLER_ACTION_HTTP_PROXY           5

typedef struct
{
    const char *action_name;
    int action;
} action_item_t;

action_item_t action_list[] = {
    { "none", HANDLER_ACTION_NONE },
    { "drop", HANDLER_ACTION_DROP },
    { "replace", HANDLER_ACTION_REPLACE },
    { "hex_replace", HANDLER_ACTION_HEX_REPLACE },
    { "http_replace", HANDLER_ACTION_HTTP_REPLACE },
    { "http_proxy", HANDLER_ACTION_HTTP_PROXY },
    { NULL,  0},
};

typedef struct
{
    int action;
    const char *search_string;
    const char *new_string;
    const char *head_file;
    const char *body_file;
} handler_t;

void print_compiler_error(
    int error_level,
    const char* file_name,
    int line_number,
    const char* message)
{
    if (error_level == YARA_ERROR_LEVEL_ERROR)
    {
        fprintf(stderr, "%s(%d): error: %s\n", file_name, line_number, message);
    }
    else
    {
        fprintf(stderr, "%s(%d): warning: %s\n", file_name, line_number, message);
    }
}

void print_scanner_error(int error)
{
    switch (error)
    {
    case ERROR_SUCCESS:
        break;
    case ERROR_COULD_NOT_ATTACH_TO_PROCESS:
        fprintf(stderr, "can not attach to process (try running as root)\n");
        break;
    case ERROR_INSUFICIENT_MEMORY:
        fprintf(stderr, "not enough memory\n");
        break;
    case ERROR_SCAN_TIMEOUT:
        fprintf(stderr, "scanning timed out\n");
        break;
    case ERROR_COULD_NOT_OPEN_FILE:
        fprintf(stderr, "could not open file\n");
        break;
    case ERROR_UNSUPPORTED_FILE_VERSION:
        fprintf(stderr, "rules were compiled with a newer version of YARA.\n");
        break;
    case ERROR_CORRUPT_FILE:
        fprintf(stderr, "corrupt compiled rules file.\n");
        break;
    default:
        fprintf(stderr, "internal error: %d\n", error);
        break;
    }
}

void parse_rule_handler(YR_RULE* rule, handler_t *handler)
{
    memset(handler, 0, sizeof(handler_t));

    for (YR_META *meta = rule->metas; !META_IS_NULL(meta); meta++)
    {
        if (meta->type == META_TYPE_STRING)
        {
            if (0 == strcmp(meta->identifier, "action"))
            {
                for (int i = 0; i < sizeof(action_list) / sizeof(action_item_t); i++)
                {
                    if (action_list[i].action_name == NULL)
                    {
                        break;
                    }
                    if (0 == strcmp(meta->string, action_list[i].action_name))
                    {
                        handler->action = action_list[i].action;
                        break;
                    }
                }
            }
            else if(0 == strcmp(meta->identifier, "search_string"))
            {
                handler->search_string = meta->string;
            }
            else if (0 == strcmp(meta->identifier, "new_string"))
            {
                handler->new_string = meta->string;
            }
            else if (0 == strcmp(meta->identifier, "head_file"))
            {
                handler->head_file = meta->string;
            }
            else if (0 == strcmp(meta->identifier, "body_file"))
            {
                handler->body_file = meta->string;
            }
        }
    }
}

int get_handler_callback(int message, YR_RULE* rule, void* data)
{
    switch (message)
    {
    case CALLBACK_MSG_RULE_MATCHING:
        printf("match callback: %s\n",
            message == CALLBACK_MSG_RULE_MATCHING ? "Match" : "Not Match");
        parse_rule_handler(rule, (handler_t *)data);
        return CALLBACK_CONTINUE;
        break;
    case CALLBACK_MSG_RULE_NOT_MATCHING:
        return CALLBACK_CONTINUE;
        break;
    default:
        return CALLBACK_ERROR;
        break;
    }
}

YR_RULES *parse_rule_file(const char *filename)
{
    YR_COMPILER* compiler = NULL;
    YR_RULES* rules = NULL;
    FILE* rule_fp = NULL;
    int result = 0;

    do
    {
        if (ERROR_SUCCESS != yr_compiler_create(&compiler))
        {
            break;
        }
        
        rule_fp = fopen(filename, "r");
        if (rule_fp == NULL)
        {
            fprintf(stderr, "error: could not open file: %s\n", filename);
            break;
        }

        compiler->error_report_function = print_compiler_error;
        yr_compiler_push_file_name(compiler, filename);
        result = yr_compiler_add_file(compiler, rule_fp, NULL);

        fclose(rule_fp);
        rule_fp = NULL;

        if (result > 0)
        {
            break;
        }

        result = yr_compiler_get_rules(compiler, &rules);

        yr_compiler_destroy(compiler);
        compiler = NULL;

        if (result != ERROR_SUCCESS)
        {
            break;
        }

        return rules;
    } 
    while (FALSE);

    if (rules != NULL)
    {
        yr_rules_destroy(rules);
    }

    if (rule_fp != NULL)
    {
        fclose(rule_fp);
    }

    if (compiler != NULL)
    {
        yr_compiler_destroy(compiler);
    }

    return NULL;
}

int get_handler(YR_RULES *rules, unsigned char *data, int length, handler_t *handler)
{
    int result;
    
    memset(handler, 0, sizeof(handler_t));
    result = yr_rules_scan_mem(
        rules,
        data,
        length,
        get_handler_callback,
        (void *)handler,
        0,
        0);

    if (result != ERROR_SUCCESS)
    {
        fprintf(stderr, "Error when scanning");
        print_scanner_error(result);
        return EXIT_FAILURE;
    }
    
    return ERROR_SUCCESS;
}

unsigned char *mem_search(unsigned char *buf, int buf_len, const unsigned char *pat, int pat_len)
{
    for (int i = 0; i < buf_len - pat_len; i++)
    {
        if (0 == memcmp(buf + i, pat, pat_len))
        {
            return buf + i;
        }
    }
    return NULL;
}

int hex_value(unsigned char c)
{
    if (c >= 'A' && c <= 'Z')
    {
        return c - 'A' + 10;
    }
    else if (c >= 'a' && c <= 'z')
    {
        return c - 'a' + 10;
    }
    else if (c >= '0' && c <= 'f')
    {
        return c - '0';
    }
    else
    {
        return 0;
    }
}

int hex_memcmp(unsigned char *buf, const unsigned char *hex, int hex_len)
{
    int result;
    unsigned char c;
    int phase = 0;

    for (int off = 0; off < hex_len; off++)
    {
        if (isxdigit(hex[off]))
        {
            if (phase == 0)
            {
                c = c * 16 + hex_value(hex[off]);
                if (*buf > c)
                {
                    return 1;
                }
                else if (*buf < c)
                {
                    return -1;
                }
                buf++;
                phase = 1;
            }
            else
            {
                c = hex_value(hex[off]);
                phase = 0;
            }
        }
    }

    return 0;
}

unsigned char *hex_mem_search(unsigned char *buf, 
    int buf_len, 
    const unsigned char *hex_pat, 
    int hex_pat_len)
{
    for (int i = 0; i < buf_len; i++)
    {
        if (0 == hex_memcmp(buf + i, hex_pat, hex_pat_len))
        {
            return buf + i;
        }
    }
    return NULL;
}

int filter_data(YR_RULES *rules, 
    unsigned char *data, 
    int length, 
    HANDLER_USER_CONTEXT *context)
{
    int off;
    handler_t handler;
    unsigned char * pmatch;
    int result;

    get_handler(rules, data, length, &handler);
    if (handler.action == HANDLER_ACTION_DROP)
    {
        result = FILTER_DROP;
    }
    else if (handler.action == HANDLER_ACTION_REPLACE)
    {
        pmatch = mem_search(data,
            length, 
            (unsigned char *)handler.search_string, 
            strlen(handler.search_string));
        if (pmatch != NULL)
        {
            memcpy(pmatch, handler.new_string, strlen(handler.new_string));
        }
        result = FILTER_PASS;
    }
    else if (handler.action == HANDLER_ACTION_HEX_REPLACE)
    {
        pmatch = hex_mem_search(data,
            length,
            (unsigned char *)handler.search_string,
            strlen(handler.search_string));
        if (pmatch != NULL)
        {
            memcpy(pmatch, handler.new_string, strlen(handler.new_string));
        }

        result = FILTER_PASS;
    }
    else if (handler.action == HANDLER_ACTION_HTTP_REPLACE)
    {
        fprintf(stdout, "Found matched data.\n");
        int len = 1024 * 1024 * 20;
        unsigned char *p = (unsigned char *)malloc(len);
        if (p != NULL)
        {
            off = load_http_from_file(p, len, handler.head_file, handler.body_file, 1);
            write_file("sender.data", p, len);
            context->send_cb(context->to, p, off);
            free(p);
        }

        result = FILTER_DROP;
    }
    else if (handler.action == HANDLER_ACTION_HTTP_PROXY)
    {
        fprintf(stdout, "Found matched data.\n");
        int len = 1024 * 1024 * 20;
        unsigned char *p = (unsigned char *)malloc(len);
        if (p != NULL)
        {
            off = load_http_from_file(p, len, handler.head_file, handler.body_file, 1);
            write_file("responder.data", p, len);
            context->send_cb(context->from, p, off);
            free(p);
        }

        result = FILTER_DROP;
    }

    return result;
}

int lock_filter_data(lock_rules_t *lock_rules, 
    unsigned char *data, 
    int length, 
    HANDLER_USER_CONTEXT *context)
{
    int result;

    pthread_mutex_lock(&lock_rules->mutex);
    result = filter_data(lock_rules->rules, data, length, context);
    pthread_mutex_unlock(&lock_rules->mutex);

    return result;
}

void scan_text(unsigned char *text, int length, const char *rule_file)
{
    YR_RULES* rules = NULL;

    yr_initialize();

    rules = parse_rule_file(rule_file);

    if (rules != NULL)
    {
        filter_data(rules, text, length, NULL);

        yr_rules_destroy(rules);
        rules = NULL;
    }

    yr_finalize();
}

int test_filter()
{
    unsigned char text[] = "GET /market/GetBinary/GetBinary/org.wikipedia.beta"
        "Host: android.clients.google.com";
    fprintf(stdout, "calling test_filter...\n");
    scan_text(text, strlen((char *)text), "etc/rules/client.rules");
    return 0;
}
