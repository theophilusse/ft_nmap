#ifndef UDP_H
# define UDP_H

typedef struct __attribute__((packed)) s_udp {
    uint16_t source;
    uint16_t dest;
    uint16_t length;
    uint16_t checksum;
} t_udp;

#endif
