#include "ft_nmap.h"

const char  *scan_type_to_str(int scan_type)
{
    if (scan_type == SCAN_SYN)  return ("SYN");
    if (scan_type == SCAN_NULL) return ("NULL");
    if (scan_type == SCAN_FIN)  return ("FIN");
    if (scan_type == SCAN_XMAS) return ("XMAS");
    if (scan_type == SCAN_ACK)  return ("ACK");
    if (scan_type == SCAN_UDP)  return ("UDP");
    return ("Unknown");
}

const char  *result_to_str(int result)
{
    if (result == PORT_OPEN)          return ("Open");
    if (result == PORT_CLOSED)        return ("Closed");
    if (result == PORT_FILTERED)      return ("Filtered");
    if (result == PORT_UNFILTERED)    return ("Unfiltered");
    if (result == PORT_OPEN_FILTERED) return ("Open|Filtered");
    return ("Unknown");
}

uint16_t    checksum(void *data, int len)
{
    uint32_t    sum;
    uint16_t    *ptr;

    sum = 0;
    ptr = (uint16_t *)data;
    while (len > 1)
    {
        sum += *ptr++;
        len -= 2;
    }
    if (len == 1)
        sum += *(uint8_t *)ptr;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (~sum);
}

void    print_usage(void)
{
    printf("Usage: ft_nmap [OPTION...]\n");
    printf("Scan open ports on a host.\n");
    printf("\n");
    printf("  -v --verbose          Verbose output\n");
    printf("  -i --ip <address>     IPv4 address or hostname to scan\n");
    printf("  -f --file  <file>     File containing list of IPv4 addresses/hostnames to scan\n");
    printf("  -p --ports <ports>    Ports to scan (eg: 1-1024 or 80 or 80,443 or 1,5-15)\n");
    printf("                        Default: 1-1024 | Max: 1024 ports\n");
    printf("  -t --speedup <number> Number of parallel threads to use (default: 0, max: 250)\n");
    printf("  -s --scan  <type>     Scan type(s): SYN, NULL, FIN, XMAS, ACK, UDP\n");
    printf("                        Combinable: --scan SYN,FIN or --scan SYN --scan FIN\n");
    printf("                        Default: all scan types\n");
    printf("  -d --dns              DNS resolution / version detection\n");
    printf("  -z --os               OS detection\n");
    printf("  -b --decoy <address>  Hide source address (spoof/decoy)\n");
    printf("  -e --ids-evasion      Techniques to bypass IDS/Firewall\n");
    printf("\n");
    printf("  -?, --help         Give this help list\n");
    printf("\n");
    printf("Report bugs to <ttrossea@42.fr>.\n");
}
