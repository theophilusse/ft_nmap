#include "ft_nmap.h"

static struct option long_opts[] = {
    { "verbose", no_argument, 0, 'v' },
    { "help",        no_argument,       0, 'h' },
    { "ip",          required_argument, 0, 'i' },
    { "file",        required_argument, 0, 'f' },
    { "ports",       required_argument, 0, 'p' },
    { "speedup",     required_argument, 0, 't' },
    { "scan",        required_argument, 0, 's' },
    // Bonus
    { "dns",         no_argument,       0, 'd' },
    { "os",          no_argument,       0, 'z' },
    { "decoy",       required_argument, 0, 'b' },
    { "ids-evasion", no_argument,       0, 'e' },
    { 0, 0, 0, 0 }
};

static int  parse_scan(t_opts *opts, char *arg)
{
    char    *token;
    char    *str;

    str = strdup(arg);
    if (!str)
        return (-1);
    token = strtok(str, ",");
    while (token)
    {
        if (!strcasecmp(token, "SYN"))   opts->scans |= SCAN_SYN;
        else if (!strcasecmp(token, "NULL"))  opts->scans |= SCAN_NULL;
        else if (!strcasecmp(token, "FIN"))   opts->scans |= SCAN_FIN;
        else if (!strcasecmp(token, "XMAS"))  opts->scans |= SCAN_XMAS;
        else if (!strcasecmp(token, "ACK"))   opts->scans |= SCAN_ACK;
        else if (!strcasecmp(token, "UDP"))   opts->scans |= SCAN_UDP;
        else
        {
            fprintf(stderr, "ft_nmap: unknown scan type: %s\n", token);
            free(str);
            return (-1);
        }
        token = strtok(NULL, ",");
    }
    free(str);
    return (0);
}

static int  parse_ports(t_opts *opts, char *arg)
{
    char        *token;
    char        *str;
    char        *dash;
    int         start;
    int         end;

    str = strdup(arg);
    if (!str)
        return (-1);
    token = strtok(str, ",");
    while (token)
    {
        dash = strchr(token, '-');
        if (dash)
        {
            *dash = '\0';
            start = atoi(token);
            end = atoi(dash + 1);
            if (start < 1 || end > 65535 || start > end)
            {
                fprintf(stderr, "ft_nmap: invalid port range: %s-%s\n", token, dash + 1);
                free(str);
                return (-1);
            }
            while (start <= end)
            {
                if (opts->port_count >= 1024)
                {
                    fprintf(stderr, "ft_nmap: max 1024 ports\n");
                    free(str);
                    return (-1);
                }
                opts->ports[opts->port_count++] = (uint16_t)start++;
            }
        }
        else
        {
            start = atoi(token);
            if (start < 1 || start > 65535)
            {
                fprintf(stderr, "ft_nmap: invalid port: %s\n", token);
                free(str);
                return (-1);
            }
            if (opts->port_count >= 1024)
            {
                fprintf(stderr, "ft_nmap: max 1024 ports\n");
                free(str);
                return (-1);
            }
            opts->ports[opts->port_count++] = (uint16_t)start;
        }
        token = strtok(NULL, ",");
    }
    free(str);
    return (0);
}

static int  parse_file(t_opts *opts, char *filename)
{
    FILE    *f;
    char    line[256];

    f = fopen(filename, "r");
    if (!f)
    {
        fprintf(stderr, "ft_nmap: cannot open file: %s\n", filename);
        return (-1);
    }
    while (fgets(line, sizeof(line), f))
    {
        line[strcspn(line, "\n")] = '\0';
        if (line[0] == '\0' || line[0] == '#')
            continue ;
        opts->hosts = add_host(opts->hosts, line);
        if (!opts->hosts)
        {
            fclose(f);
            return (-1);
        }
	opts->host_count++;
    }
    fclose(f);
    if (opts->host_count == 0)
    {
        fprintf(stderr, "ft_nmap: no valid host in file\n");
        return (-1);
    }
    return (0);
}

int parse_opts(t_opts *opts, int ac, char **av)
{
    int     c;
    int     opt_index;
    char    *ip;
    char    *file;

    ip = NULL;
    file = NULL;
    memset(opts, 0, sizeof(t_opts));

    while ((c = getopt_long(ac, av, "", long_opts, &opt_index)) != -1)
    {
        if (c == 'h')       { print_usage(); return (1); }
        else if (c == 'v')  opts->verbose = 1;
        else if (c == 'i')  ip = optarg;
        else if (c == 'f')  { if (parse_file(opts, optarg) < 0) return (-1); file = optarg; }
        else if (c == 'p')  { if (parse_ports(opts, optarg) < 0) return (-1); }
        else if (c == 's')  opts->speedup = atoi(optarg);
        else if (c == 'S')  { if (parse_scan(opts, optarg) < 0) return (-1); }
        else if (c == 'd')  opts->dns = 1;
        else if (c == 'o')  opts->os = 1;
        else if (c == 'D')
        {
            struct sockaddr_in *sin = (struct sockaddr_in *)&opts->decoy;
            sin->sin_family = AF_INET;
            if (inet_pton(AF_INET, optarg, &sin->sin_addr) != 1)
            {
                fprintf(stderr, "ft_nmap: invalid decoy address: %s\n", optarg);
                return (-1);
            }
        }
        else if (c == 'I')  opts->ids_evasion = 1;
        else                { fprintf(stderr, "ft_nmap: unknown option\n"); return (-1); }
    }

    // Validations
    if (ip && file)
    {
        fprintf(stderr, "ft_nmap: --ip and --file are mutually exclusive\n");
        return (-1);
    }
    if (!ip && !opts->hosts)
    {
        fprintf(stderr, "ft_nmap: --ip or --file is required\n");
        return (-1);
    }
    if (ip)
    {
        opts->hosts = add_host(opts->hosts, ip);
        if (!opts->hosts)
            return (-1);
        opts->host_count++;
    }
    if (opts->port_count == 0)
    {
        // default: 1-1024
        opts->port_count = 1024;
        for (int i = 0; i < 1024; i++)
            opts->ports[i] = (uint16_t)(i + 1);
    }
    if (opts->scans == 0)
        opts->scans = SCAN_ALL;
    if (opts->speedup < 0 || opts->speedup > 250)
    {
        fprintf(stderr, "ft_nmap: speedup must be between 0 and 250\n");
        return (-1);
    }
    return (0);
}
