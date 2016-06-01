#include "dump_socket.h"
#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include "packet_headers.h"
#include "packet_check.h"
#include <netinet/in.h>
#include <sys/time.h>

#define min(x,y) ((x) > (y) ? (y) : (x))
#define max(x,y) ((x) > (y) ? (x) : (y))

#define DIRECTION_SEND      0
#define DIRECTION_RECV      1

#define FETCH_SOURCE        1
#define FETCH_DESTINATION   2

#define vsocket_t socket_dumper_t

void *pcap_dumper = NULL;
pthread_mutex_t pcap_mutex = PTHREAD_MUTEX_INITIALIZER;

int fetch_ipid(socket_dumper_t *dumper, int direction)
{
    return direction == DIRECTION_SEND ? dumper->local_ipid++ : dumper->remote_ipid++;
}

unsigned char *get_mac(socket_dumper_t *dumper, int fetch_type, int direction)
{
    if (fetch_type == FETCH_SOURCE)
    {
        return direction == DIRECTION_SEND ? dumper->src_mac : dumper->dest_mac;
    }
    else
    {
        return direction == DIRECTION_SEND ? dumper->dest_mac : dumper->src_mac;
    }
}

int get_ip(socket_dumper_t *dumper, int fetch_type, int direction)
{
    if (fetch_type == FETCH_SOURCE)
    {
        return direction == DIRECTION_SEND ? dumper->src_ip : dumper->dest_ip;
    }
    else
    {
        return direction == DIRECTION_SEND ? dumper->dest_ip : dumper->src_ip;
    }
}

int get_port(socket_dumper_t *dumper, int fetch_type, int direction)
{
    if (fetch_type == FETCH_SOURCE)
    {
        return direction == DIRECTION_SEND ? dumper->src_port : dumper->dest_port;
    }
    else
    {
        return direction == DIRECTION_SEND ? dumper->dest_port : dumper->src_port;
    }
}

unsigned int get_seq_no(socket_dumper_t *dumper, int direction)
{
    return direction == DIRECTION_SEND ? dumper->seq_no : dumper->ack_no;
}

unsigned int get_ack_no(socket_dumper_t *dumper, int direction)
{
    return direction == DIRECTION_SEND ? dumper->ack_no : dumper->seq_no;
}

unsigned int add_seq_no(socket_dumper_t *dumper, int direction, int value)
{
    if (direction == DIRECTION_SEND)
    {
        dumper->seq_no = htonl(ntohl(dumper->seq_no) + value);
    }
    else
    {
        dumper->ack_no = htonl(ntohl(dumper->ack_no) + value);
    }
}

int build_tcp_packet(unsigned char *buffer,
    int length,
    vsocket_t *sock,
    const unsigned char *payload_buffer,
    int payload_length,
    int flags,
    int *pbuilt,
    int direction)
{
    tcphdr_t *tcp_header;
    int offset;

    tcp_header = (tcphdr_t*)buffer;

    tcp_header->th_sport = get_port(sock, FETCH_SOURCE, direction);
    tcp_header->th_dport = get_port(sock, FETCH_DESTINATION, direction);
    tcp_header->th_seq = get_seq_no(sock, direction);
    tcp_header->th_ack = get_ack_no(sock, direction);
    tcp_header->th_off = sizeof(tcphdr_t) / 4;
    tcp_header->th_x2 = 0;
    tcp_header->th_flags = flags;
    tcp_header->th_win = htons(0xFFFE);
    tcp_header->th_urp = 0;

    offset = sizeof(tcphdr_t);

    if (payload_buffer != NULL && payload_length > 0)
    {
        int copy_length = min(length - offset, payload_length);
        if (copy_length > 0)
        {
            memcpy(buffer + offset, payload_buffer, copy_length);
            offset += copy_length;
        }

        *pbuilt = copy_length;
        add_seq_no(sock, direction, copy_length);
    }
    else
    {
        *pbuilt = 0;
    }

    return offset;
}

int build_ip_packet(unsigned char *buffer,
    int length,
    vsocket_t *sock,
    const unsigned char *payload,
    int payload_len,
    int flags,
    int *pbuilt,
    int direction)
{
    iphdr_t * ip_header;
    int off;

    ip_header = (iphdr_t *)buffer;
    ip_header->ip_v = 4;
    ip_header->ip_hl = sizeof(iphdr_t) / 4;
    ip_header->ip_tos = 0;
    ip_header->ip_id = htons(fetch_ipid(sock, direction));
    ip_header->ip_off = 0x0040;
    ip_header->ip_ttl = 0x80;
    ip_header->ip_p = IPPROTO_TCP;
    ip_header->ip_src = get_ip(sock, FETCH_SOURCE, direction);
    ip_header->ip_dst = get_ip(sock, FETCH_DESTINATION, direction);

    off = sizeof(iphdr_t);

    off += build_tcp_packet(buffer + off,
        length - off,
        sock,
        payload,
        payload_len,
        flags,
        pbuilt,
        direction);

    ip_header->ip_len = htons(off);
    //tcp_checksum
    libnet_do_checksum((u_char *)ip_header, IPPROTO_TCP, ntohs(ip_header->ip_len) - ip_header->ip_hl * 4);
    //ip checksum
    libnet_do_checksum((u_char *)ip_header, IPPROTO_IP, ip_header->ip_hl * 4);

    return off;
}

int build_ethernet_packet(unsigned char *buffer,
    int length,
    vsocket_t *sock,
    const unsigned char *payload,
    int payload_len,
    int flags,
    int *pbuilt,
    int direction)
{
    ethhdr_t * mac_header;
    int off;
    int diff;

    mac_header = (ethhdr_t *)buffer;
    memcpy(mac_header->ether_shost, get_mac(sock, FETCH_SOURCE, direction), 6);
    memcpy(mac_header->ether_dhost, get_mac(sock, FETCH_DESTINATION, direction), 6);
    mac_header->ether_type = 0x0008;
    off = sizeof(ethhdr_t);

    off += build_ip_packet(buffer + off, length - off, sock, payload, payload_len, flags, pbuilt, direction);

    if (off < 60)
    {
        diff = 60 - off;
        memset(buffer + off, 0, diff);
        off += diff;
    }

    return off;
}

void socket_dumper_build(vsocket_t *sock, const unsigned char *buf, int len, int direction, int flags)
{
    unsigned char pkt[2048];
    struct pcap_pkthdr hdr;
    void *dumper;
    int pkt_len;
    int built;
    int offset;

    dumper = sock->dumper;
    if (dumper == NULL)
    {
        return;
    }

    offset = 0;

    do
    {
        built = 0;
        pkt_len = build_ethernet_packet(pkt,
            1500+14,
            sock,
            buf + offset,
            len - offset,
            flags,
            &built,
            direction);

        if (buf != NULL && len > 0 && built > 0)
        {
            offset += built;
        }

        if (pkt_len > 0)
        {
            memset(&hdr, 0, sizeof(hdr));
            gettimeofday(&hdr.ts, NULL);
            hdr.caplen = pkt_len;
            hdr.len = pkt_len;
            pcap_dump((u_char *)dumper, &hdr, pkt);
        }
    } 
    while (buf != NULL && len > 0 && offset < len);
    pcap_dump_flush((pcap_dumper_t *)dumper);
}

void socket_dumper_init(vsocket_t *sock,
    unsigned int session_id,
    unsigned int client_ip,
    int client_port,
    unsigned int server_ip,
    int server_port,
    void *dumper)
{
    sock->local_ipid = rand();
    sock->remote_ipid = rand();

    sock->seq_no = rand();
    sock->ack_no = rand();

    sock->src_ip = client_ip;
    sock->src_port = client_port;
    sock->dest_ip = server_ip;
    sock->dest_port = server_port;

    memset(sock->src_mac, 0xEE, 6);
    memset(sock->dest_mac, 0x00, 6);
    memcpy(sock->dest_mac, &session_id, sizeof(session_id)); // hide session id in destination MAC address

    sock->dumper = dumper;
}

void socket_dumper_recv(vsocket_t *sock, const unsigned char *buf, int len)
{
    socket_dumper_build(sock, buf, len, DIRECTION_RECV, TH_PUSH | TH_ACK);
}

void socket_dumper_send(vsocket_t *sock, const unsigned char *buf, int len)
{
    socket_dumper_build(sock, buf, len, DIRECTION_SEND, TH_PUSH | TH_ACK);
}

void *open_pcap_file(const char *filename)
{
    return pcap_dump_open(pcap_open_dead(DLT_EN10MB, 16384 /* MTU */),
        filename);
}

void close_pcap_file(void *pcap_dumper)
{
    pcap_dump_close((pcap_dumper_t *)pcap_dumper);
}

void socket_dumper_close(vsocket_t *sock)
{
    memset(sock, 0, sizeof(vsocket_t));
}
