#include "ft_nmap.h"

const char  *detect_os(t_os_info *os)
{
    if (!os->has_data)
        return ("Unknown");

    // TTL based
    if (os->ttl <= 64)
    {
        if (os->window == 29200 || os->window == 5840)
            return ("Linux 3.x/4.x");
        if (os->window == 14600)
            return ("Linux 2.6.x");
        return ("Linux/Unix");
    }
    if (os->ttl <= 128)
    {
        if (os->window == 8192)
            return ("Windows 7/8/10");
        if (os->window == 65535)
            return ("Windows XP/2003");
        return ("Windows");
    }
    if (os->ttl <= 255)
    {
        if (os->window == 65535)
            return ("macOS/FreeBSD");
        if (os->window == 16384)
            return ("macOS");
        return ("BSD/Cisco");
    }
    return ("Unknown");
}
