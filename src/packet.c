#include "ft_nmap.h"

void    build_ip(t_ip *ip, uint32_t src, uint32_t dst,
                 uint8_t protocol, uint16_t payload_len)
{
    memset(ip, 0, sizeof(t_ip));
    ip->ihl      = 5;
    ip->version  = 4;
    ip->tos      = 0;
# ifndef __linux__
    ip->tot_len  = sizeof(t_ip) + payload_len;
    ip->id       = rand() % 65535;
# else
    ip->tot_len  = htons(sizeof(t_ip) + payload_len);
    ip->id       = htons(rand() % 65535);
# endif
    ip->frag_off = 0;
    ip->ttl      = 64;
    ip->protocol = protocol;
    ip->checksum = 0;

    // Decoy : remplace l'IP source si --decoy est activé
    if (g_opts.decoy.sa_family == AF_INET)
        ip->src = ((struct sockaddr_in *)&g_opts.decoy)->sin_addr.s_addr;
    else
        ip->src = src;

    ip->dst      = dst;
    ip->checksum = checksum(ip, sizeof(t_ip));
}