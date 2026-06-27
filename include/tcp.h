#ifndef TCP_H
# define TCP_H

# define TH_FIN  0x001
# define TH_SYN  0x002
# define TH_RST  0x004
# define TH_PSH  0x008
# define TH_ACK  0x010
# define TH_URG  0x020

typedef struct __attribute__((packed)) s_tcp {
    uint16_t	source;
    uint16_t	dest;
    uint32_t	seq;
    uint32_t	ack;
    uint16_t    flags;
    uint16_t    window;
    uint16_t    checksum;
    uint16_t    urg_ptr;
} t_tcp;

#endif
