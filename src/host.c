#include "ft_nmap.h"

t_host   *new_host(char *name)
{
    t_host  *host;

    host = malloc(sizeof(t_host));
    if (!host)
        return (NULL);
    host->name = strdup(name);
    host->next = NULL;
    return (host);
}

void	free_host(t_host *host)
{
    t_host *p;

    while (host)
    {
        if (host->name)
            free(host->name);
        p = host;
        host = host->next;
        free(p);
    }
}

t_host  *add_host(t_host *head, char *name)
{
    t_host  *new;
    t_host  *cur;

    new = new_host(name);
    if (!new)
        return (NULL);
    if (!head)
        return (new);
    cur = head;
    while (cur->next)
        cur = cur->next;
    cur->next = new;
    return (head);
}

