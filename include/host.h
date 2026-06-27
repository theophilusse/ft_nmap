#ifndef HOST_H
# define HOST_H

typedef struct s_host
{
    char            *name;
    struct s_host   *next;
}   t_host;

t_host	*new_host(char *name);
t_host	*add_host(t_host *host, char *name);
void	free_host(t_host *host);

#endif
