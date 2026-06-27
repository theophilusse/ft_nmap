#ifndef FT_NMAP_H
# define FT_NMAP_H
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <netdb.h>
# include <sys/time.h>
# include <signal.h>
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <unistd.h>
# include <stdint.h>
# include <getopt.h>
# include <errno.h>
# include <ifaddrs.h>
# include <sys/select.h>
# include <pcap.h>
# include <pthread.h>

# define GET_LOCAL_IP(ip) do { \
    struct ifaddrs *ifap, *ifa; \
    getifaddrs(&ifap); \
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) { \
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) { \
            struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr; \
            if (sa->sin_addr.s_addr != htonl(INADDR_LOOPBACK)) { \
                (ip) = sa->sin_addr; \
                g_opts.iface_name = strdup(ifa->ifa_name); \
                break; \
            } \
        } \
    } \
    freeifaddrs(ifap); \
} while(0)

# ifdef __linux__

#  include <linux/if.h>
#  define BIND_IFACE(fd, iface) \
    setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen(iface))
#  define RAW_PROTOCOL(p) (p)
# else
#  include <fcntl.h>
#  include <sys/ioctl.h>
#  include <net/if.h>
#  define BIND_IFACE(fd, iface) ({ \
    unsigned int idx = if_nametoindex(iface); \
    setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &idx, sizeof(idx)); \
})
#  define RAW_PROTOCOL(p) IPPROTO_RAW
#  define MACOS_HDRINCL_FIX 1
# endif

# define PORT_OPEN          0
# define PORT_CLOSED        1
# define PORT_FILTERED      2
# define PORT_UNFILTERED    3
# define PORT_OPEN_FILTERED 4

# include "ip.h"
# include "tcp.h"
# include "icmp.h"
# include "udp.h"
# include "pseudo.h"
# include "host.h"
# include "opts.h"
# include "thread.h"
# include "result.h"
# include "services.h"
# include "host.h"
# include "print.h"
# include "send.h"
# include "capture.h"
# include "packet.h"
# include "dns.h"
# include "os.h"
# include "utils.h"

void    print_usage(void);
uint16_t    checksum(void *data, int len);

extern t_opts   g_opts;

#endif
