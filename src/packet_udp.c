#include "ft_nmap.h"

static uint16_t udp_checksum(t_ip *ip, t_udp *udp)
{
    t_pseudo_udp    pseudo;
    uint8_t         buf[sizeof(t_pseudo_udp) + sizeof(t_udp)];

    pseudo.src      = ip->src;
    pseudo.dst      = ip->dst;
    pseudo.zero     = 0;
    pseudo.protocol = IPPROTO_UDP;
    pseudo.udp_len  = htons(sizeof(t_udp));

    memcpy(buf, &pseudo, sizeof(t_pseudo_udp));
    memcpy(buf + sizeof(t_pseudo_udp), udp, sizeof(t_udp));
    return (checksum(buf, sizeof(buf)));
}

static void build_ip_udp(t_ip *ip, uint32_t src, uint32_t dst)
{
    memset(ip, 0, sizeof(t_ip));
    ip->ihl      = 5;
    ip->version  = 4;
    ip->tos      = 0;
    ip->tot_len  = htons(sizeof(t_ip) + sizeof(t_udp));
    ip->id       = htons(rand() % 65535);
    ip->frag_off = 0;
    ip->ttl      = 64;
    ip->protocol = IPPROTO_UDP;
    ip->checksum = 0;
    ip->src      = src;
    ip->dst      = dst;
    ip->checksum = checksum(ip, sizeof(t_ip));
}

static void build_udp(t_udp *udp, t_ip *ip, uint16_t src_port, uint16_t dst_port)
{
    memset(udp, 0, sizeof(t_udp));
    udp->source   = htons(src_port);
    udp->dest     = htons(dst_port);
    udp->length   = htons(sizeof(t_udp));
    udp->checksum = 0;
    udp->checksum = udp_checksum(ip, udp);
}

int build_udp_packet(uint8_t *buf, uint32_t src, uint32_t dst,
                     uint16_t src_port, uint16_t dst_port)
{
    t_ip    *ip;
    t_udp   *udp;

    ip  = (t_ip *)buf;
    udp = (t_udp *)(buf + sizeof(t_ip));
    build_ip_udp(ip, src, dst);
    build_udp(udp, ip, src_port, dst_port);
    return (sizeof(t_ip) + sizeof(t_udp));
}
