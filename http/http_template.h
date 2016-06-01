#ifndef HTTP_TEMPLATE_H
#define HTTP_TEMPLATE_H

#ifdef __cplusplus
extern "C"
{
#endif

int load_http_from_file(unsigned char *buf, int len, const char *head_file, const char *body_file, int use_gzip);
void write_file(const char *filename, unsigned char *buffer, int length);

#ifdef __cplusplus
}
#endif

#endif
