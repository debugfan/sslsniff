//---------------------------------------------------------------------------

#ifndef PACKET_CHECK_H
#define PACKET_CHECK_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "types_def.h"
#ifdef WIN32
#include "inet_in.h"
#else
#include <netinet/in.h>
typedef	u_int32_t n_time;		/* ms since 00:00 GMT, byte rev */
#endif

//---------------------------------------------------------------------------

unsigned int libnet_in_cksum(u_int16_t *addr, int len);

u_int16_t libnet_ip_check(u_int16_t *addr, int len);

unsigned short do_check_sum(void* buffer, int len);

int libnet_do_checksum(u_int8_t *buf, int protocol, int len);

int tcp_full_check(unsigned char *buf, int len);

#ifdef __cplusplus
}
#endif 

#endif
