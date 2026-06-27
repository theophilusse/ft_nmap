#include "ft_nmap.h"

int scan_type_to_index(int scan_type)
{
    if (scan_type == SCAN_SYN)  return (SCAN_IDX_SYN);
    if (scan_type == SCAN_NULL) return (SCAN_IDX_NULL);
    if (scan_type == SCAN_FIN)  return (SCAN_IDX_FIN);
    if (scan_type == SCAN_XMAS) return (SCAN_IDX_XMAS);
    if (scan_type == SCAN_ACK)  return (SCAN_IDX_ACK);
    if (scan_type == SCAN_UDP)  return (SCAN_IDX_UDP);
    return (-1);
}

void    set_result(t_thread *th, uint16_t port, int scan_type, int result)
{
    int idx;

    idx = scan_type_to_index(scan_type);
    if (idx < 0)
        return ;
    pthread_mutex_lock(&th->result.mutex);
    th->result.results[port][idx] = result;
    pthread_mutex_unlock(&th->result.mutex);
}

int     get_result(t_thread *th, uint16_t port, int scan_type)
{
    int idx;
    int result;

    idx = scan_type_to_index(scan_type);
    if (idx < 0)
        return (-1);
    pthread_mutex_lock(&th->result.mutex);
    result = th->result.results[port][idx];
    pthread_mutex_unlock(&th->result.mutex);
    return (result);
}
