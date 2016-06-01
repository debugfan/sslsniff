#include "http_template.h"
#include "mango.h"
#include <string.h>
#include <stdlib.h>
#include "lstring.h"
#include <stdio.h>

#ifdef WIN32

#define itoa(i, a, l, r) _itoa(i, a, r)

#else

void strrev(unsigned char *str)
{
	int i;
	int j;
	unsigned char a;
	unsigned len = strlen((const char *)str);
	for (i = 0, j = len - 1; i < j; i++, j--)
	{
		a = str[i];
		str[i] = str[j];
		str[j] = a;
	}
}

int itoa(int num, unsigned char* str, int len, int base)
{
	int sum = num;
	int i = 0;
	int digit;
	if (len == 0)
		return -1;
	do
	{
		digit = sum % base;
		if (digit < 0xA)
			str[i++] = '0' + digit;
		else
			str[i++] = 'A' + digit - 0xA;
		sum /= base;
	}while (sum && (i < (len - 1)));
	if (i == (len - 1) && sum)
		return -1;
	str[i] = '\0';
	strrev(str);
	return 0;
}

#endif

int http_expand(unsigned char *buf, int len, 
    const char *head, int head_len, 
    const char *body, int body_len)
{
    mango_context_t templ_ctx;
    char len_str[32];
    int off;

    mango_init(&templ_ctx);
    itoa(body_len, len_str, sizeof(len_str), 10);
    mango_set_dictionary_pair(&templ_ctx, "Content-Length", len_str);
    off = mango_parse(&templ_ctx, buf, len, head, head_len);
    memcpy(buf + off, body, body_len);
    off += body_len;
    mango_finish(&templ_ctx);
    return off;
}

int fsize(FILE *fp)
{
    int prev = ftell(fp);
    fseek(fp, 0L, SEEK_END);
    int sz = ftell(fp);
    fseek(fp, prev, SEEK_SET); //go back to where we were
    return sz;
}

int read_file(const char *filename, lstring *lstr)
{
    FILE *fp = NULL;
    char *buf = NULL;
    int len = 0;
    int off_read;
    fp = fopen(filename, "rb");
    if (fp != NULL)
    {
        len = fsize(fp);
        if (len > 0)
        {
            buf = (unsigned char *)malloc(len + 1);
            if (buf != NULL)
            {
                off_read = fread(buf, 1, len, fp);
                if (off_read < len)
                {
                    fprintf(stdout, "Bytes of read is less than expected.\n");
                }
            }
        }
        fclose(fp);
    }

    lstr_assign(lstr, buf, len);

    return len;
}

int gzip_compress(const char *filename, const char *gzname)
{
    char command[512];
    sprintf(command, "gzip -c %s > %s", filename, gzname);
    fprintf(stdout, "%s\n", command);
    return system(command);
}

int load_http_from_file(unsigned char *buf, int len, const char *head_file, const char *body_file, int use_gzip)
{
    lstring head;
    lstring body;
    char gzip_name[260];
    int off;

    read_file(head_file, &head);
    if (use_gzip != 0)
    {
        sprintf(gzip_name, "%s.gz", body_file);
        gzip_compress(body_file, gzip_name);
        read_file(gzip_name, &body);
    }
    else
    {
        read_file(body_file, &body);
    }
    off = http_expand(buf, len, head.data, head.len, body.data, body.len);
    lstr_free(&head);
    lstr_free(&body);
    return off;
}

void write_file(const char *filename, unsigned char *buffer, int length)
{
    FILE *fp;
    fp = fopen(filename, "wb");
    if (fp != NULL)
    {
        fwrite(buffer, 1, length, fp);
        fclose(fp);
    }
}
