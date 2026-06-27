#ifndef CAPTURE_H
# define CAPTURE_H
# include <pcap.h>
# include <stdint.h>

typedef struct s_capture {
    uint32_t    src_ip;
    uint32_t    dst_ip;
    uint16_t    dst_port;
    int         scan_type;
    int         result;
    int         done;
    int         datalink;
    uint8_t     ttl;        // pour OS detection
    uint16_t    window;     // pour OS detection
} t_capture;

pcap_t  *open_capture(uint32_t dst_ip, uint16_t dst_port, int scan_type);
int wait_capture(pcap_t *handle, uint32_t dst_ip, uint16_t dst_port,
                 int scan_type, t_os_info *os);
#endif