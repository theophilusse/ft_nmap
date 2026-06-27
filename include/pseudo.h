#ifndef PSEUDO_H
# define PSEUDO_H

typedef struct __attribute__((packed)) s_pseudo_udp {
    uint32_t    src;
    uint32_t    dst;
    uint8_t     zero;
    uint8_t     protocol;
    uint16_t    udp_len;
} t_pseudo_udp;

#endif
