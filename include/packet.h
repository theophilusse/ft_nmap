#ifndef PACKET_H
# define PACKET_H

# include <stdint.h>
# include "ip.h"

int         build_tcp_packet(uint8_t *buf, uint32_t src, uint32_t dst,
                             uint16_t src_port, uint16_t dst_port,
                             uint16_t th_flags);
int         build_udp_packet(uint8_t *buf, uint32_t src, uint32_t dst,
                             uint16_t src_port, uint16_t dst_port);
uint16_t    scan_to_flags(int scan_type);
uint16_t    checksum(void *data, int len);
void        build_ip(t_ip *ip, uint32_t src, uint32_t dst,
                     uint8_t protocol, uint16_t payload_len);

#endif
