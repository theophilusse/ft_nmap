#include "ft_nmap.h"

t_service   *load_services(void)
{
    FILE        *f;
    char        line[256];
    char        name[32];
    int         port;
    char        proto[16];
    t_service   *head;
    t_service   *node;

    head = NULL;
    f = fopen("/etc/services", "r");
    if (!f)
        return (NULL);
    while (fgets(line, sizeof(line), f))
    {
        if (line[0] == '#' || line[0] == '\n')
            continue ;
        if (sscanf(line, "%31s %d/%15s", name, &port, proto) != 3)
            continue ;
        node = malloc(sizeof(t_service));
        if (!node)
            break ;
        node->port = (uint16_t)port;
        strncpy(node->name, name, sizeof(node->name) - 1);
        node->name[sizeof(node->name) - 1] = '\0';
        node->next = head;
        head = node;
    }
    fclose(f);
    return (head);
}

const char  *get_service_name(t_service *services, uint16_t port)
{
    t_service   *cur;

    cur = services;
    while (cur)
    {
        if (cur->port == port)
            return (cur->name);
        cur = cur->next;
    }
    return ("Unassigned");
}

void        free_services(t_service *services)
{
    t_service   *next;

    while (services)
    {
        next = services->next;
        free(services);
        services = next;
    }
}
