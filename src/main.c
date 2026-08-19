#include "ft_nmap.h"

t_opts  g_opts;

static double   get_elapsed(struct timeval *start)
{
    struct timeval  end;

    gettimeofday(&end, NULL);
    return ((end.tv_sec - start->tv_sec)
            + (end.tv_usec - start->tv_usec) / 1000000.0);
}

static int  resolve_host(const char *host, uint32_t *dst_ip)
{
    struct addrinfo     hints;
    struct addrinfo     *res;
    struct sockaddr_in  *sin;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_RAW;
    if (getaddrinfo(host, NULL, &hints, &res) != 0)
    {
        fprintf(stderr, "ft_nmap: cannot resolve host: %s\n", host);
        return (-1);
    }
    sin     = (struct sockaddr_in *)res->ai_addr;
    *dst_ip = sin->sin_addr.s_addr;
    freeaddrinfo(res);
    return (0);
}

static int  scan_host(t_host *host, t_service *services)
{
    uint32_t        dst_ip;
    t_thread        *th;
    struct timeval  start;
    double          elapsed;

    if (resolve_host(host->name, &dst_ip) < 0)
        return (-1);
    th = malloc(sizeof(t_thread));
    if (!th)
        return (-1);
    if (thread_init(th) < 0)
    {
        free(th);
        return (-1);
    }
    print_scan_config(dst_ip);
    gettimeofday(&start, NULL);
    if (run_scan(th, dst_ip) < 0)
    {
        thread_destroy(th);
        free(th);
        return (-1);
    }
    elapsed = get_elapsed(&start);
    print_results(th, dst_ip, services, elapsed);
    thread_destroy(th);
    free(th);
    return (0);
}

int main(int ac, char **av)
{
    t_host      *host;
    t_service   *services;

    if (geteuid() != 0)
    {
        fprintf(stderr, "ft_nmap: must be run as root\n");
        return (1);
    }
    srand(time(NULL));
    memset(&g_opts, 0, sizeof(g_opts));
    if (parse_opts(&g_opts, ac, av) < 0)
        return (1);
    GET_LOCAL_IP(g_opts.local_ip);
    if (!g_opts.iface_name)
    {
        fprintf(stderr, "ft_nmap: cannot find local interface\n");
        return (1);
    }
    services = load_services();
    host = g_opts.hosts;
    while (host)
    {
        scan_host(host, services);
        host = host->next;
    }
    free_services(services);
    free_host(g_opts.hosts);
    if (g_opts.iface_name)
        free(g_opts.iface_name);
    return (0);
}
