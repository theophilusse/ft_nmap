#ifndef __linux__
# include <net/bpf.h>
#endif
#include "ft_nmap.h"

int send_packet(uint8_t *buf, int len, uint32_t dst, int protocol)
{
    struct sockaddr_in  target;
    int                 sock;
    int                 one;

    memset(&target, 0, sizeof(target));
    target.sin_family      = AF_INET;
    target.sin_addr.s_addr = dst;
    target.sin_port        = 0;

#ifdef __linux__
    (void)protocol;
    one  = 1;
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0)
    {
        fprintf(stderr, "ft_nmap: socket: %s\n", strerror(errno));
        return (-1);
    }
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
        fprintf(stderr, "ft_nmap: setsockopt: %s\n", strerror(errno));
        close(sock);
        return (-1);
    }
    if (sendto(sock, buf, len, 0,
               (struct sockaddr *)&target, sizeof(target)) < 0)
    {
        fprintf(stderr, "ft_nmap: sendto: %s\n", strerror(errno));
        close(sock);
        return (-1);
    }
#else
    one = 0;
    if (one)
        one++;
    if (protocol == IPPROTO_UDP)
    {
        udp  = (t_udp *)(buf + sizeof(t_ip));
        sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0)
        {
            fprintf(stderr, "ft_nmap: socket: %s\n", strerror(errno));
            return (-1);
        }
        target.sin_port = udp->dest;
        if (sendto(sock, NULL, 0, 0,
                   (struct sockaddr *)&target, sizeof(target)) < 0)
        {
            fprintf(stderr, "ft_nmap: sendto UDP: %s\n", strerror(errno));
            close(sock);
            return (-1);
        }
    }
    else
    {
        // SOCK_RAW sans IP_HDRINCL : on envoie TCP header seulement
        // le kernel ajoute le header IP
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sock < 0)
        {
            fprintf(stderr, "ft_nmap: socket: %s\n", strerror(errno));
            return (-1);
        }
        if (sendto(sock, buf + sizeof(t_ip), len - sizeof(t_ip), 0,
                   (struct sockaddr *)&target, sizeof(target)) < 0)
        {
            fprintf(stderr, "ft_nmap: sendto TCP: %s\n", strerror(errno));
            close(sock);
            return (-1);
        }
    }
#endif
    close(sock);
    return (0);
}
