#ifndef ICMP_H
# define ICMP_H

typedef struct __attribute__((packed)) s_icmp {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
} t_icmp;

#endif
