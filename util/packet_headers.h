#ifndef PACKET_HEADERS_H
#define PACKET_HEADERS_H

#define	__packed	__attribute__((__packed__))
#define __aligned(x)	__attribute__((__aligned__(x)))

/* Length of an ethernet address. */
#ifndef ETHER_ADDR_LEN
#define	ETHER_ADDR_LEN	6
#endif


/*
* Definitions for byte order, according to byte significance from low
* address to high.
*/
#define	_LITTLE_ENDIAN	1234	/* LSB first: i386, vax */
#define	_BIG_ENDIAN	4321	/* MSB first: 68000, ibm, net */
#define	_PDP_ENDIAN	3412	/* LSB first in word, MSW first in long */

#define	_BYTE_ORDER	_LITTLE_ENDIAN

#define	LITTLE_ENDIAN	_LITTLE_ENDIAN
#define	BIG_ENDIAN	_BIG_ENDIAN
#define	PDP_ENDIAN	_PDP_ENDIAN
#define	BYTE_ORDER	_BYTE_ORDER

/*
* Structure of a 10Mb/s Ethernet header.
*/
struct ether_header {
    u_char	ether_dhost[ETHER_ADDR_LEN];
    u_char	ether_shost[ETHER_ADDR_LEN];
    u_short	ether_type;
} __packed;

/*
* Structure of an internet header, naked of options.
*/
struct ip {
#if BYTE_ORDER == LITTLE_ENDIAN
    u_char	ip_hl : 4,		/* header length */
    ip_v : 4;			/* version */
#endif
#if BYTE_ORDER == BIG_ENDIAN
    u_char	ip_v : 4,			/* version */
    ip_hl : 4;		/* header length */
#endif
    u_char	ip_tos;			/* type of service */
    u_short	ip_len;			/* total length */
    u_short	ip_id;			/* identification */
    u_short	ip_off;			/* fragment offset field */
#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
    u_char	ip_ttl;			/* time to live */
    u_char	ip_p;			/* protocol */
    u_short	ip_sum;			/* checksum */
    //struct	in_addr ip_src, ip_dst;	/* source and dest address */
    unsigned int ip_src, ip_dst;
} __packed __aligned(4);

typedef	u_int32_t tcp_seq;

/*
* TCP header.
* Per RFC 793, September, 1981.
*/
struct tcphdr {
    u_short	th_sport;		/* source port */
    u_short	th_dport;		/* destination port */
    tcp_seq	th_seq;			/* sequence number */
    tcp_seq	th_ack;			/* acknowledgement number */
#if BYTE_ORDER == LITTLE_ENDIAN
    u_char	th_x2 : 4,		/* (unused) */
    th_off : 4;		/* data offset */
#endif
#if BYTE_ORDER == BIG_ENDIAN
    u_char	th_off : 4,		/* data offset */
    th_x2 : 4;		/* (unused) */
#endif
    u_char	th_flags;
#define	TH_FIN	0x01
#define	TH_SYN	0x02
#define	TH_RST	0x04
#define	TH_PUSH	0x08
#define	TH_ACK	0x10
#define	TH_URG	0x20
#define	TH_ECE	0x40
#define	TH_CWR	0x80
#define	TH_FLAGS	(TH_FIN|TH_SYN|TH_RST|TH_PUSH|TH_ACK|TH_URG|TH_ECE|TH_CWR)
#define	PRINT_TH_FLAGS	"\20\1FIN\2SYN\3RST\4PUSH\5ACK\6URG\7ECE\10CWR"

    u_short	th_win;			/* window */
    u_short	th_sum;			/* checksum */
    u_short	th_urp;			/* urgent pointer */
};

/*
* UDP protocol header.
* Per RFC 768, September, 1981.
*/
struct udphdr {
    u_short	uh_sport;		/* source port */
    u_short	uh_dport;		/* destination port */
    u_short	uh_ulen;		/* udp length */
    u_short	uh_sum;			/* udp checksum */
};


typedef	struct	tcphdr	tcphdr_t;
typedef	struct	udphdr	udphdr_t;
typedef	struct	icmp	icmphdr_t;
typedef	struct	ip	ip_t;
typedef	struct	ether_header	ether_header_t;

typedef ip_t iphdr_t;
typedef	ether_header_t	ethhdr_t;

#endif
