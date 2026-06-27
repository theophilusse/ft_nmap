#include "ft_nmap.h"

static int  conclude_port(t_thread *th, uint16_t port)
{
    int open;
    int filtered;
    int s;

    open     = 0;
    filtered = 0;
    for (s = 0; s < 6; s++)
    {
        if (!(g_opts.scans & (1 << s)))
            continue ;
        int r = get_result(th, port, (1 << s));
        if (r == PORT_OPEN)
            open = 1;
        if (r == PORT_FILTERED || r == PORT_OPEN_FILTERED)
            filtered = 1;
    }
    if (open)
        return (PORT_OPEN);
    if (filtered)
        return (PORT_FILTERED);
    return (PORT_CLOSED);
}

static void print_separator(void)
{
    printf("%-*s %-*s %-*s %-*s\n",
           COL_PORT,    "Port",
           COL_SERVICE, "Service",
           COL_RESULTS, "Results",
           COL_CONCL,   "Conclusion");
    int total = COL_PORT + COL_SERVICE + COL_RESULTS + COL_CONCL + 3;
    for (int i = 0; i < total; i++)
        printf("-");
    printf("\n");
}

static void print_port_line(t_thread *th, uint16_t port,
                             t_service *services, uint32_t dst_ip)
{
    char    results[256];
    char    tmp[64];
    char    *banner;
    int     s;
    int     first;

    results[0] = '\0';
    first = 1;
    for (s = 0; s < 6; s++)
    {
        if (!(g_opts.scans & (1 << s)))
            continue ;
        int r = get_result(th, port, (1 << s));
        snprintf(tmp, sizeof(tmp), "%s%s(%s)",
                 first ? "" : " ",
                 scan_type_to_str(1 << s),
                 result_to_str(r));
        strncat(results, tmp, sizeof(results) - strlen(results) - 1);
        first = 0;
    }
    banner = NULL;
    if (g_opts.dns && conclude_port(th, port) == PORT_OPEN)
        banner = grab_banner(dst_ip, port);
    printf("%-*d %-*s %-*s %-*s %s\n",
           COL_PORT,    port,
           COL_SERVICE, get_service_name(services, port),
           COL_RESULTS, results,
           COL_CONCL,   result_to_str(conclude_port(th, port)),
           banner ? banner : "");
    if (banner)
        free(banner);
}

void    print_scan_config(uint32_t dst_ip)
{
    struct in_addr  addr;
    char            *hostname;
    int             s;

    addr.s_addr = dst_ip;
    printf("\nScan Configurations\n");
    printf("Target Ip-Address   : %s\n", inet_ntoa(addr));
    if (g_opts.dns)
    {
        hostname = reverse_dns(dst_ip);
        if (hostname)
        {
            printf("Hostname            : %s\n", hostname);
            free(hostname);
        }
    }
    printf("No of Ports to scan : %d\n", g_opts.port_count);
    printf("Scans to be performed : ");
    for (s = 0; s < 6; s++)
    {
        if (g_opts.scans & (1 << s))
            printf("%s ", scan_type_to_str(1 << s));
    }
    printf("\nNo of threads       : %d\n\n", g_opts.speedup);
    printf("Scanning..\n");
}

void    print_results(t_thread *th, uint32_t dst_ip,
                      t_service *services, double elapsed)
{
    struct in_addr  addr;
    int             i;
    int             conclusion;

    addr.s_addr = dst_ip;
    printf("\nScan took %.5f secs\n", elapsed);
    printf("IP address: %s\n\n", inet_ntoa(addr));
    if (g_opts.os && th->result.os.has_data)
        printf("OS Detection        : %s (TTL=%d Window=%d)\n",
            detect_os(&th->result.os),
            th->result.os.ttl,
            th->result.os.window);

    printf("Open ports:\n");
    print_separator();
    for (i = 0; i < g_opts.port_count; i++)
    {
        conclusion = conclude_port(th, g_opts.ports[i]);
        if (conclusion == PORT_OPEN)
            print_port_line(th, g_opts.ports[i], services, dst_ip);
    }

    printf("\nClosed/Filtered/Unfiltered ports:\n");
    print_separator();
    for (i = 0; i < g_opts.port_count; i++)
    {
        conclusion = conclude_port(th, g_opts.ports[i]);
        if (g_opts.verbose)
        {
            if (conclusion != PORT_OPEN)
                print_port_line(th, g_opts.ports[i], services, dst_ip);
        }
        else if (conclusion == PORT_FILTERED)
                print_port_line(th, g_opts.ports[i], services, dst_ip);
    }
}
