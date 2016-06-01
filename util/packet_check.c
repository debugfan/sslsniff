//---------------------------------------------------------------------------
//#include "precomp.h"
#include "packet_check.h"
#define LIBNET_LIL_ENDIAN 1
#include "libnet-macros.h"
#include "libnet-headers.h"
#include "packet_headers.h"
#include <stdlib.h>

#ifdef __BORLANDC__
#pragma hdrstop
#endif
//---------------------------------------------------------------------------

#ifdef __BORLANDC__
#pragma package(smart_init)
#endif

/* FIXME - unit test these - 0 is debian's version, else is -RC1's */
unsigned int
libnet_in_cksum(u_int16_t *addr, int len)
{
    unsigned int sum;
#if 0
    u_int16_t last_byte;

    sum = 0;
    last_byte = 0;
#else
    union
    {
        u_int16_t s;
        u_int8_t b[2];
    }pad;

    sum = 0;
#endif

    while (len > 1)
    {
        sum += *addr++;
        len -= 2;
    }
#if 0
    if (len == 1)
    {
        *(u_int8_t *)&last_byte = *(u_int8_t *)addr;
        sum += last_byte;
    }
#else
    if (len == 1)
    {
        pad.b[0] = *(u_int8_t *)addr;
        pad.b[1] = 0;
        sum += pad.s;
    }
#endif

    return (sum);
}

u_int16_t
libnet_ip_check(u_int16_t *addr, int len)
{
    //u_int16_t sum;
	unsigned int sum;

    sum = libnet_in_cksum(addr, len);
    return (LIBNET_CKSUM_CARRY(sum));
}

//unsigned short do_check_sum(void* buffer, int len)
//{
//	char buffer2[128] = { 0 };
//	psd_header* psd = (psd_header*)buffer2;
//	psd->sourceip = inet_addr(SRCIP);
//	psd->destip = inet_addr(DSTIP);
//	psd->ptcl = IPPROTO_TCP;
//	//psd->plen =  htons(sizeof(tcp_header));
//	psd->plen =  htons(len);
//
//	//memcpy(buffer2 + sizeof(psd_header), buffer, sizeof(tcp_header));
//	memcpy(buffer2 + sizeof(psd_header), buffer, len);
//
//	//return CheckSum((u_int16_t*)buffer2, sizeof(psd_header) + sizeof(tcp_header));
//	return CheckSum((u_int16_t*)buffer2, sizeof(psd_header) + len);
//}

int
libnet_do_checksum(u_int8_t *buf, int protocol, int len)
{
    /* will need to update this for ipv6 at some point */
    struct libnet_ipv4_hdr *iph_p;
    struct libnet_ipv6_hdr *ip6h_p;
    int is_ipv6;
    int ip_hl;
    unsigned int sum;

    is_ipv6 = 0;    /* default to not using IPv6 */
    sum     = 0;
    iph_p   = NULL;
    ip6h_p  = NULL;

    if (len == 0)
    {
//        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
//            "%s(): header length can't be zero\n", __func__);
        return (-1);
    }

    /*
     *  Figure out which IP version we're dealing with.  We'll assume v4
     *  and overlay a header structure to yank out the version.
     */
    iph_p = (struct libnet_ipv4_hdr *)buf;
    if (iph_p && iph_p->ip_v == 6)
    {
        ip6h_p = (struct libnet_ipv6_hdr *)buf;
        is_ipv6 = 1;
        ip_hl   = 40;
    }
    else
    {
        is_ipv6 = 0;
        ip_hl = iph_p->ip_hl << 2;
    }

    /*
     *  Dug Song came up with this very cool checksuming implementation
     *  eliminating the need for explicit psuedoheader use.  Check it out.
     */
    switch (protocol)
    {
        /*
         *  Style note: normally I don't advocate declaring variables inside
         *  blocks of control, but it makes good sense here. -- MDS
         */
        case IPPROTO_TCP:
        {
            struct libnet_tcp_hdr *tcph_p =
                (struct libnet_tcp_hdr *)(buf + ip_hl);

#if (STUPID_SOLARIS_CHECKSUM_BUG)
            tcph_p->th_sum = tcph_p->th_off << 2;
            return (1);
#endif /* STUPID_SOLARIS_CHECKSUM_BUG */
#if (HAVE_HPUX11)
            if (l->injection_type != LIBNET_LINK)
            {
                /*
                 *  Similiar to the Solaris Checksum bug - but need to add
                 *  the size of the TCP payload (only for raw sockets).
                 */
                tcph_p->th_sum = (tcph_p->th_off << 2) +
                        (len - (tcph_p->th_off << 2));
                return (1); 
            }
#endif
            tcph_p->th_sum = 0;
            if (is_ipv6)
            {
                sum = libnet_in_cksum((u_int16_t *)&ip6h_p->ip_src, 32);
            }
            else
            {
                sum = libnet_in_cksum((u_int16_t *)&iph_p->ip_src, 8);
            }
            sum += ntohs(IPPROTO_TCP + len);
            sum += libnet_in_cksum((u_int16_t *)tcph_p, len);
            tcph_p->th_sum = LIBNET_CKSUM_CARRY(sum);
            break;
        }
        case IPPROTO_UDP:
        {
            struct libnet_udp_hdr *udph_p =
                (struct libnet_udp_hdr *)(buf + ip_hl);
            udph_p->uh_sum = 0;
            if (is_ipv6)
            {
                sum = libnet_in_cksum((u_int16_t *)&ip6h_p->ip_src, 32);
            }
            else
            {
                sum = libnet_in_cksum((u_int16_t *)&iph_p->ip_src, 8);
            }
            sum += ntohs(IPPROTO_UDP + len);
            sum += libnet_in_cksum((u_int16_t *)udph_p, len);
            udph_p->uh_sum = LIBNET_CKSUM_CARRY(sum);
            break;
        }
        case IPPROTO_ICMP:
        {
            struct libnet_icmpv4_hdr *icmph_p =
                (struct libnet_icmpv4_hdr *)(buf + ip_hl);

            icmph_p->icmp_sum = 0;
            if (is_ipv6)
            {
                sum = libnet_in_cksum((u_int16_t *)&ip6h_p->ip_src, 32);
                sum += ntohs(IPPROTO_ICMP6 + len);
            }
            sum += libnet_in_cksum((u_int16_t *)icmph_p, len);
            icmph_p->icmp_sum = LIBNET_CKSUM_CARRY(sum);
            break;
        }
        case IPPROTO_IGMP:
        {
            struct libnet_igmp_hdr *igmph_p =
                (struct libnet_igmp_hdr *)(buf + ip_hl);

            igmph_p->igmp_sum = 0;
            sum = libnet_in_cksum((u_int16_t *)igmph_p, len);
            igmph_p->igmp_sum = LIBNET_CKSUM_CARRY(sum);
            break;
        }
	case IPPROTO_GRE:
	{
            /* checksum is always at the same place in GRE header
             * in the multiple RFC version of the protocol ... ouf !!!
             */
	    struct libnet_gre_hdr *greh_p = 
		(struct libnet_gre_hdr *)(buf + ip_hl);
	    u_int16_t fv = ntohs(greh_p->flags_ver);
	    if (!(fv & (GRE_CSUM|GRE_ROUTING | GRE_VERSION_0)) ||
                !(fv & (GRE_CSUM|GRE_VERSION_1)))
	    {
//		snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
//                "%s(): can't compute GRE checksum (wrong flags_ver bits: 0x%x )\n",  __func__, fv);
		return (-1);
	    }
	    sum = libnet_in_cksum((u_int16_t *)greh_p, len);
	    greh_p->gre_sum = LIBNET_CKSUM_CARRY(sum);
	    break;
	}
        case IPPROTO_OSPF:
        {
            struct libnet_ospf_hdr *oh_p =
                (struct libnet_ospf_hdr *)(buf + ip_hl);

            oh_p->ospf_sum = 0;
            sum += libnet_in_cksum((u_int16_t *)oh_p, len);
            oh_p->ospf_sum = LIBNET_CKSUM_CARRY(sum);
            break;
        }
        case IPPROTO_OSPF_LSA:
        {
            struct libnet_ospf_hdr *oh_p =
                (struct libnet_ospf_hdr *)(buf + ip_hl);
            struct libnet_lsa_hdr *lsa_p =
                (struct libnet_lsa_hdr *)(buf + 
                ip_hl + oh_p->ospf_len);

            lsa_p->lsa_sum = 0;
            sum += libnet_in_cksum((u_int16_t *)lsa_p, len);
            lsa_p->lsa_sum = LIBNET_CKSUM_CARRY(sum);
            break;
#if 0
            /*
             *  Reworked fletcher checksum taken from RFC 1008.
             */
            int c0, c1;
            struct libnet_lsa_hdr *lsa_p = (struct libnet_lsa_hdr *)buf;
            u_int8_t *p, *p1, *p2, *p3;

            c0 = 0;
            c1 = 0;

            lsa_p->lsa_cksum = 0;

            p = buf;
            p1 = buf;
            p3 = buf + len;             /* beginning and end of buf */

            while (p1 < p3)
            {
                p2 = p1 + LIBNET_MODX;
                if (p2 > p3)
                {
                    p2 = p3;
                }
  
                for (p = p1; p < p2; p++)
                {
                    c0 += (*p);
                    c1 += c0;
                }

                c0 %= 255;
                c1 %= 255;      /* modular 255 */
 
                p1 = p2;
            }

#if AWR_PLEASE_REWORK_THIS
            lsa_p->lsa_cksum[0] = (((len - 17) * c0 - c1) % 255);
            if (lsa_p->lsa_cksum[0] <= 0)
            {
                lsa_p->lsa_cksum[0] += 255;
            }

            lsa_p->lsa_cksum[1] = (510 - c0 - lsa_p->lsa_cksum[0]);
            if (lsa_p->lsa_cksum[1] > 255)
            {
                lsa_p->lsa_cksum[1] -= 255;
            }
#endif
            break;
#endif
        }
        case IPPROTO_IP:
        {
            iph_p->ip_sum = 0;
            sum = libnet_in_cksum((u_int16_t *)iph_p, ip_hl);
            iph_p->ip_sum = LIBNET_CKSUM_CARRY(sum);
            break;
        }
        case IPPROTO_VRRP:
        {
            struct libnet_vrrp_hdr *vrrph_p =
                (struct libnet_vrrp_hdr *)(buf + ip_hl);

            vrrph_p->vrrp_sum = 0;
            sum = libnet_in_cksum((u_int16_t *)vrrph_p, len);
            vrrph_p->vrrp_sum = LIBNET_CKSUM_CARRY(sum);
            break;
        }
        case LIBNET_PROTO_CDP:
        {   /* XXX - Broken: how can we easily get the entire packet size? */
            struct libnet_cdp_hdr *cdph_p =
                (struct libnet_cdp_hdr *)buf;

            cdph_p->cdp_sum = 0;
            sum = libnet_in_cksum((u_int16_t *)cdph_p, len);
            cdph_p->cdp_sum = LIBNET_CKSUM_CARRY(sum);
            break;
        }
        case LIBNET_PROTO_ISL:
        {
#if 0
            struct libnet_isl_hdr *islh_p =
                (struct libnet_isl_hdr *)buf;
#endif
            /*
             *  Need to compute 4 byte CRC for the ethernet frame and for
             *  the ISL frame itself.  Use the libnet_crc function.
             */
        }
        default:
        {
//            snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
//                "%s(): unsuported protocol %d\n", __func__, protocol);
            return (-1);
        }
    }
    return (1);
}

int ip_full_check(unsigned char *buf, int len)
{
    ethhdr_t* pether_header;
    iphdr_t* pip_header;

    pether_header = (ethhdr_t *)buf;
    if (pether_header->ether_type == 0x0008)
    {
        pip_header = (iphdr_t*)(buf + sizeof(ethhdr_t));
        if (sizeof(ethhdr_t) + sizeof(iphdr_t) <= len)
        {
            libnet_do_checksum((u_char *)pip_header, pip_header->ip_p, ntohs(pip_header->ip_len) - pip_header->ip_hl * 4);
            libnet_do_checksum((u_char *)pip_header, IPPROTO_IP, pip_header->ip_hl * 4);
            return 1;
        }
    }
    return 0;
}

///* Data putting routines -- these put data into the send/receive buffer.
//
// * It's all big-endian. */
//// modify to little-endian
//
//void put_char (variable_buffer *buf, int *offset, int x)
//{
//    buf->memcpy(*offset, &x, 1);
//    (*offset)++;
//}
//
//void put_short (variable_buffer *buf, int *offset, int x)
//{
//    u_short value = htons(x);
//    buf->memcpy(*offset, &value, 2);
//    (*offset) = (*offset) + 2;
//}
//
//void put_long (variable_buffer *buf, int *offset, int x)
//{
//    u_long value = htonl(x);
//    buf->memcpy(*offset, &value, 4);
//    (*offset) = (*offset) + 4;
//}
//
//void put_str(variable_buffer *buf, int *offset, CONST char *s)
//{
//    int len = strlen(s);
//    buf->memcpy(*offset, s, len);
//    *offset += len;
//}
//
//void put_data(variable_buffer *buf, int *offset, CONST u_char *data, int len)
//{
//    buf->memcpy(*offset, data, len);
//    *offset += len;
//}
//
//
//void put_hostname (variable_buffer *buf, int *offset,CONST char *hostname)
//
//{
//
//    u_char *p, *q;
//
//    if ((!offset) || (*offset < 0)) return;
//
//    if (*hostname == 0)
//    {
//        (*buf)[(*offset)++] = 0;
//        return;
//    }
//
//    //strcpy (buf + *offset + 1, hostname);
//    buf->memcpy(*offset + 1, hostname, strlen(hostname)+1);
//
//    p = buf->offset(0) + *offset;
//    q = p + 1;
//    do
//    {
//        while (*q && (*q != '.')) q++;
//        *p = q - (p + 1);
//        p = q++;
//    } while (*p);
//
//    *offset = ((unsigned char *)q) - buf->offset(0);
//}
//
//
//void put_query (variable_buffer *buf, int *offset,CONST struct dns_query *query)
//
//{
//
//	put_hostname (buf, offset, (*query).qname);
//	put_short    (buf, offset, (*query).qtype);
//	put_short    (buf, offset, (*query).qclass);
//}
//
//
//void put_dns_packet (variable_buffer * buf, int *offset,CONST struct dns_packet *q)
//
//{
//
//	put_short (buf, offset, q->id);
//	put_short (buf, offset, q->flags.i);
//	put_short (buf, offset, q->qdcount);
//	put_short (buf, offset, 0);             /* q->ancount */
//	put_short (buf, offset, 0);             /* q->nscount */
//	put_short (buf, offset, 0);             /* q->arcount */
//
//	for (int i = 0; i < q->qdcount; i++)
//    {
//        put_query (buf, offset,q->questions + i);
//    }
//}
