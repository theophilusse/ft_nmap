#include "ft_nmap.h"

char    *reverse_dns(uint32_t ip)
{
    struct sockaddr_in  sa;
    char                host[NI_MAXHOST];

    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = ip;
    if (getnameinfo((struct sockaddr *)&sa, sizeof(sa),
                    host, sizeof(host), NULL, 0, 0) != 0)
        return (NULL);
    return (strdup(host));
}

char    *grab_banner(uint32_t ip, uint16_t port)
{
    struct sockaddr_in  sa;
    int                 sock;
    char                *banner;
    char                buf[256];
    struct timeval      tv;
    ssize_t             n;

    banner = NULL;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        return (NULL);
    tv.tv_sec  = 2;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = ip;
    sa.sin_port        = htons(port);
    if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0)
    {
        close(sock);
        return (NULL);
    }
    memset(buf, 0, sizeof(buf));
    n = recv(sock, buf, sizeof(buf) - 1, 0);
    if (n <= 0)
    {
        // Certains services (HTTP) nécessitent une requête d'abord
        send(sock, "HEAD / HTTP/1.0\r\n\r\n", 19, 0);
        n = recv(sock, buf, sizeof(buf) - 1, 0);
    }
    if (n > 0)
    {
        buf[n] = '\0';
        // Garde seulement la première ligne
        char *nl = strchr(buf, '\n');
        if (nl) *nl = '\0';
        nl = strchr(buf, '\r');
        if (nl) *nl = '\0';
        banner = strdup(buf);
    }
    close(sock);
    return (banner);
}
