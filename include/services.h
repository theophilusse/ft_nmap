#ifndef SERVICES_H
# define SERVICES_H

typedef struct s_service {
    uint16_t        port;
    char            name[32];
    struct s_service *next;
} t_service;

t_service   *load_services(void);
const char  *get_service_name(t_service *services, uint16_t port);
void        free_services(t_service *services);

#endif
