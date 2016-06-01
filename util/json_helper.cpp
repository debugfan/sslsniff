#include "json_helper.h"
#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <time.h>

FILE *json_fp = NULL;
pthread_mutex_t json_mutex = PTHREAD_MUTEX_INITIALIZER;

volatile unsigned int id = 0;

#define JSON_ITEM_START "{"
#define JSON_ITEM_END   "}\n"
#define JSON_SEPERATOR  ", "

void json_write_string(FILE *fp, const void *buf, int len)
{
    fwrite(buf, 1, len, fp);
}

#define json_write_seperator(fp) json_write_string(fp, JSON_SEPERATOR, strlen(JSON_SEPERATOR));

void json_write_number_pair(FILE *fp, const char *key, int value)
{
    char buf[512];
    sprintf(buf, "\"%s\": %d", key, value);
    json_write_string(fp, buf, strlen(buf));
}

void json_write_string_pair(FILE *fp, const char *key, const char *value)
{
    char lead_key[512];
    sprintf(lead_key, "\"%s\": ", key);
    json_write_string(fp, lead_key, strlen(lead_key));
    json_write_string(fp, "\"", strlen("\""));
    json_write_string(fp, value, strlen(value));
    json_write_string(fp, "\"", strlen("\""));
}

char *hex2str(const unsigned char *buf, int len)
{
    char *s;
    int slen;
    slen = len * 2 + 1;
    s = (char *)malloc(slen);
    if (s != NULL)
    {
        for (int i = 0; i < len; i++)
        {
            sprintf(s + i * 2, "%02X", buf[i]);
        }
    }

    return s;
}

char *json_string(const unsigned char *buf, int len)
{
    char *s;
    int slen;
    int off;
    slen = len * 1;
    s = (char *)malloc(slen * 6 + 1);
    if (s != NULL)
    {
        off = 0;
        for (int i = 0; i < len; i++)
        {
            if (buf[i] >= 0x20 && buf[i] < 127
                && buf[i] != '\"'
                && buf[i] != '\\')
            {
                s[off] = buf[i];
                off++;
            }
            else
            {
                if (buf[i] == '\r')
                {
                    strcpy(s + off, "\\r");
                    off += strlen("\\r");
                }
                else if (buf[i] == '\n')
                {
                    strcpy(s + off, "\\n");
                    off += strlen("\\n");
                }
                else if (buf[i] == '\\')
                {
                    strcpy(s + off, "\\\\");
                    off += strlen("\\\\");
                }
                else
                {
                    sprintf(s + off, "\\u%04x", buf[i]);
                    off += strlen("\\u0000");
                }
            }
        }
        s[off] = '\0';
    }

    return s;
}

void json_write_hex_pair(FILE *fp, const char *key, const unsigned char *buf, int len)
{
    char *str;
    str = hex2str(buf, len);
    if (str != NULL)
    {
        json_write_string_pair(fp, key, str);
        free(str);
    }
}

void json_write_json_string_pair(FILE *fp, const char *key, const unsigned char *buf, int len)
{
    char *str;
    str = json_string(buf, len);
    if (str != NULL)
    {
        json_write_string_pair(fp, key, str);
        free(str);
    }
}

void json_write(FILE *fp,
    unsigned int session_id,
    const char *src_ip,
    int src_port,
    const char *dest_ip,
    int dest_port,
    const char *buf,
    int len)
{
    int new_id;
    time_t now_time;
    struct tm now_tm;
    char now_str[50];
    
    new_id = __sync_add_and_fetch(&id, 1);
    time(&now_time);
    localtime_r(&now_time, &now_tm);
    sprintf(now_str, "%04d-%02d-%02d-%02d:%02d:%02d",
        now_tm.tm_year + 1900,
        now_tm.tm_mon + 1,
        now_tm.tm_mday,
        now_tm.tm_hour,
        now_tm.tm_min,
        now_tm.tm_sec);

    json_write_string(fp, JSON_ITEM_START, strlen(JSON_ITEM_START));
    json_write_number_pair(fp, "id", new_id);
    json_write_seperator(fp);
    json_write_string_pair(fp, "time", now_str);
    json_write_seperator(fp);
    json_write_number_pair(fp, "session_id", session_id);
    json_write_seperator(fp);
    json_write_string_pair(fp, "src_ip", src_ip);
    json_write_seperator(fp);
    json_write_number_pair(fp, "src_port", src_port);
    json_write_seperator(fp);
    json_write_string_pair(fp, "dest_ip", dest_ip);
    json_write_seperator(fp);
    json_write_number_pair(fp, "dest_port", dest_port);
    json_write_seperator(fp);
    json_write_json_string_pair(fp, "json_data", (unsigned char *)buf, len);
    json_write_seperator(fp);
    json_write_hex_pair(fp, "hex_data", (unsigned char *)buf, len);
    json_write_string(fp, JSON_ITEM_END, strlen(JSON_ITEM_END));

    fflush(fp);
}
