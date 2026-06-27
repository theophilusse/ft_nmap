#ifndef PRINT_H
# define PRINT_H

# define COL_PORT    6
# define COL_SERVICE 20
# define COL_RESULTS 50
# define COL_CONCL   15
# define COL_BANNER  30

void    print_scan_config(uint32_t dst_ip);
void    print_results(t_thread *th, uint32_t dst_ip, t_service *services, double elapsed);

#endif
