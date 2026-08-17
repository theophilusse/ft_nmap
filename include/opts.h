#ifndef OPTS_H
# define OPTS_H

# include <getopt.h>
# include <netinet/in.h>

typedef struct s_opts {
    int             verbose;
    uint16_t        ports[1024];
    int             port_count;
    int             speedup;
    int             scans;
    t_host          *hosts;
    int             host_count;
    struct in_addr  local_ip;
    char            *iface_name;
    // Bonus
    int             dns;
    int             os;
    struct sockaddr decoy;
    int             ids_evasion;
} t_opts;

# define SCAN_SYN   (1 << 0)
# define SCAN_NULL  (1 << 1)
# define SCAN_FIN   (1 << 2)
# define SCAN_XMAS  (1 << 3)
# define SCAN_ACK   (1 << 4)
# define SCAN_UDP   (1 << 5)
# define SCAN_ALL   (SCAN_SYN | SCAN_NULL | SCAN_FIN | SCAN_XMAS | SCAN_ACK | SCAN_UDP)

int	parse_opts(t_opts *opts, int ac, char **av);

#endif
