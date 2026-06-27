#ifndef RESULT_H
# define RESULT_H

# define PORT_OPEN          0
# define PORT_CLOSED        1
# define PORT_FILTERED      2
# define PORT_UNFILTERED    3
# define PORT_OPEN_FILTERED 4

# define SCAN_IDX_SYN   0
# define SCAN_IDX_NULL  1
# define SCAN_IDX_FIN   2
# define SCAN_IDX_XMAS  3
# define SCAN_IDX_ACK   4
# define SCAN_IDX_UDP   5

int scan_type_to_index(int scan_type);
int get_result(t_thread *th, uint16_t port, int scan_type);
void set_result(t_thread *th, uint16_t port, int scan_type, int result);

#endif
