#include "ft_nmap.h"

static uint16_t tcp_checksum(t_ip *ip, t_tcp *tcp)
{
    t_pseudo_udp    pseudo;
    uint8_t         buf[sizeof(t_pseudo_udp) + sizeof(t_tcp)];

    pseudo.src      = ip->src;
    pseudo.dst      = ip->dst;
    pseudo.zero     = 0;
    pseudo.protocol = IPPROTO_TCP;
    pseudo.udp_len      = htons(sizeof(t_tcp));

    memcpy(buf, &pseudo, sizeof(t_pseudo_udp));
    memcpy(buf + sizeof(t_pseudo_udp), tcp, sizeof(t_tcp));
    return (checksum(buf, sizeof(buf)));
}

uint16_t    scan_to_flags(int scan_type)
{
    if (scan_type == SCAN_SYN)  return (TH_SYN);
    if (scan_type == SCAN_NULL) return (0);
    if (scan_type == SCAN_FIN)  return (TH_FIN);
    if (scan_type == SCAN_XMAS) return (TH_FIN | TH_PSH | TH_URG);
    if (scan_type == SCAN_ACK)  return (TH_ACK);
    return (0);
}

static void build_tcp(t_tcp *tcp, t_ip *ip, uint16_t src_port, uint16_t dst_port, uint16_t th_flags)
{
    memset(tcp, 0, sizeof(t_tcp));
    tcp->source   = htons(src_port);
    tcp->dest     = htons(dst_port);
    tcp->seq      = htonl(rand());
    tcp->ack      = 0;
    tcp->flags    = htons((5 << 12) | th_flags);
    tcp->window   = htons(1024);
    tcp->checksum = 0;
    tcp->urg_ptr  = 0;
    tcp->checksum = tcp_checksum(ip, tcp);
}

int build_tcp_packet(uint8_t *buf, uint32_t src, uint32_t dst,
                     uint16_t src_port, uint16_t dst_port, uint16_t th_flags)
{
    t_ip    *ip;
    t_tcp   *tcp;

    ip  = (t_ip *)buf;
    tcp = (t_tcp *)(buf + sizeof(t_ip));
    build_ip(ip, src, dst, IPPROTO_TCP, sizeof(t_tcp));
    build_tcp(tcp, ip, src_port, dst_port, th_flags);
    return (sizeof(t_ip) + sizeof(t_tcp));
}
