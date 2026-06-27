#include "ft_nmap.h"

static void packet_handler(u_char *user, const struct pcap_pkthdr *hdr,
                            const u_char *packet)
{
    t_capture   *cap;
    t_ip        *ip;
    t_tcp       *tcp;
    t_icmp      *icmp;
    uint16_t    flags;
    int         offset;

    (void)hdr;
    cap = (t_capture *)user;
    if (cap->datalink == DLT_EN10MB)
        offset = 14;
    else if (cap->datalink == DLT_NULL || cap->datalink == DLT_LOOP)
        offset = 4;
    else
        offset = 14;
    ip = (t_ip *)(packet + offset);
    if (ip->protocol == IPPROTO_TCP)
    {
        tcp   = (t_tcp *)((uint8_t *)ip + sizeof(t_ip));
        if (ntohs(tcp->source) != cap->dst_port)
            return ;
        flags = ntohs(tcp->flags) & 0x3f;
        if (cap->scan_type == SCAN_SYN)
        {
            if ((flags & TH_SYN) && (flags & TH_ACK))
            {
                cap->result = PORT_OPEN;
                cap->ttl    = ip->ttl;
                cap->window = ntohs(tcp->window);
            }
            else if (flags & TH_RST)
                cap->result = PORT_CLOSED;
        }
        else if (cap->scan_type == SCAN_ACK)
        {
            if (flags & TH_RST)
                cap->result = PORT_UNFILTERED;
        }
        else
        {
            if (flags & TH_RST)
                cap->result = PORT_CLOSED;
        }
    }
    else if (ip->protocol == IPPROTO_ICMP)
    {
        icmp = (t_icmp *)((uint8_t *)ip + sizeof(t_ip));
        if (icmp->type == 3)
            cap->result = PORT_CLOSED;
    }
    cap->done = 1;
}

pcap_t  *open_capture(uint32_t dst_ip, uint16_t dst_port, int scan_type)
{
    pcap_t              *handle;
    char                errbuf[PCAP_ERRBUF_SIZE];
    char                filter[128];
    struct bpf_program  fp;
    bpf_u_int32         mask;
    bpf_u_int32         net;

    if (dst_port)
        ;
    handle = pcap_open_live(g_opts.iface_name, 65535, 1, 100, errbuf);
    if (!handle)
    {
        fprintf(stderr, "ft_nmap: pcap_open_live: %s\n", errbuf);
        return (NULL);
    }
    pcap_lookupnet(g_opts.iface_name, &net, &mask, errbuf);
    if (scan_type == SCAN_UDP)
        snprintf(filter, sizeof(filter),
                "icmp and src host %s",
                inet_ntoa(*(struct in_addr *)&dst_ip));
    else
        snprintf(filter, sizeof(filter),
                "tcp and src host %s and src port %d",
                inet_ntoa(*(struct in_addr *)&dst_ip), dst_port);
    pcap_compile(handle, &fp, filter, 0, mask);
    pcap_setfilter(handle, &fp);
    pcap_freecode(&fp);
    pcap_setnonblock(handle, 1, errbuf);
    return (handle);
}

int wait_capture(pcap_t *handle, uint32_t dst_ip, uint16_t dst_port,
                 int scan_type, t_os_info *os)
{
    t_capture       cap;
    struct timeval  start;
    struct timeval  now;

    memset(&cap, 0, sizeof(cap));
    cap.dst_ip    = dst_ip;
    cap.dst_port  = dst_port;
    cap.scan_type = scan_type;
    cap.datalink  = pcap_datalink(handle);
    if (scan_type == SCAN_SYN || scan_type == SCAN_ACK)
        cap.result = PORT_FILTERED;
    else
        cap.result = PORT_OPEN_FILTERED;

    gettimeofday(&start, NULL);
    while (!cap.done)
    {
        pcap_dispatch(handle, 1, packet_handler, (u_char *)&cap);
        gettimeofday(&now, NULL);
        if ((now.tv_sec - start.tv_sec) >= 2)
            break ;
        usleep(1000);
    }
    pcap_close(handle);
    if (os)
    {
        os->ttl    = cap.ttl;
        os->window = cap.window;
        os->has_data = cap.ttl ? 1 : 0;
    }
    return (cap.result);
}