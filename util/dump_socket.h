#ifndef DUMP_SOCKET_H
#define DUMP_SOCKET_H

#include <pthread.h>

typedef struct
{
    unsigned char src_mac[6];
    unsigned char dest_mac[6];
    int local_ipid;
    int remote_ipid;
    unsigned int src_ip;
    unsigned int dest_ip;
    unsigned int src_port;
    unsigned int dest_port;
    unsigned int seq_no;
    unsigned int ack_no;
    void *dumper;
} socket_dumper_t;

void socket_dumper_init(socket_dumper_t *sock,
    unsigned int session_id,
    unsigned int client_ip,
    int client_port,
    unsigned int server_ip,
    int server_port,
    void *dumper);

void socket_dumper_recv(socket_dumper_t *sock, const unsigned char *buf, int len);
void socket_dumper_send(socket_dumper_t *sock, const unsigned char *buf, int len);

void *open_pcap_file(const char *filename);
void close_pcap_file(void *pcap_dumper);

void socket_dumper_close(socket_dumper_t *sock);

extern void *pcap_dumper;
extern pthread_mutex_t pcap_mutex;

#endif
