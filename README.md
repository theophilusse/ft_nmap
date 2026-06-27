# ft_nmap

A partial reimplementation of the [nmap](https://nmap.org/) port scanner, built as part of the 42 school curriculum.

## Features

### Mandatory
- **Six scan types**: SYN, NULL, FIN, XMAS, ACK, UDP
- **Multi-threaded**: up to 250 parallel threads (`--speedup`)
- **Flexible port selection**: ranges, individual ports, or combinations (`1-1024`, `80,443`, `1,5-15`)
- **File input**: scan multiple hosts from a file (`--file`)
- **Service resolution**: port-to-service name mapping via `/etc/services`
- **Clean output**: open/closed/filtered/unfiltered results per port and scan type

### Bonus
- `--dns` — reverse DNS resolution + banner grabbing (service version detection)
- `--os` — OS fingerprinting via TTL and TCP window size
- `--decoy <ip>` — spoof source IP address
- `--ids-evasion` — randomize port scan order and add random delays
- `--verbose` — real-time scan output

## Usage

```
ft_nmap [OPTIONS]

  --help                  Print this help screen
  --ip    <address>       IPv4 address or hostname to scan
  --file  <file>          File containing list of hosts to scan
  --ports <ports>         Ports to scan (default: 1-1024, max: 1024)
  --speedup <number>      Number of parallel threads (default: 0, max: 250)
  --scan  <type>          Scan type(s): SYN, NULL, FIN, XMAS, ACK, UDP
  --dns                   Enable reverse DNS + banner grabbing
  --os                    Enable OS detection
  --decoy <address>       Spoof source IP address
  --ids-evasion           Randomize scan order and add delays
  --verbose               Show results in real time
```

## Examples

```bash
# SYN scan on common ports with 50 threads
sudo ./ft_nmap --ip scanme.nmap.org --ports 22,80,443 --scan SYN --speedup 50

# Full scan with all features
sudo ./ft_nmap --ip target.com --speedup 100 --dns --os --verbose

# Scan multiple hosts from a file
sudo ./ft_nmap --file hosts.txt --ports 1-1024 --speedup 200

# Spoof source IP
sudo ./ft_nmap --ip target.com --ports 80 --scan SYN --decoy 1.2.3.4
```

## Build

```bash
make        # build
make clean  # remove objects
make fclean # remove objects and binary
make re     # rebuild
```

Requires `libpcap` and `libpthread`. Must be run as root.

```bash
sudo apt install libpcap-dev   # Debian/Ubuntu
sudo pacman -S libpcap         # Arch
```

## Requirements

- Linux kernel > 3.14 (designed and graded on Debian)
- Root privileges (`CAP_NET_RAW`)
- `libpcap`, `libpthread`

## Technical Stack

| Component | Technology |
|-----------|-----------|
| Packet crafting | Raw sockets + `IP_HDRINCL` |
| Packet capture | `libpcap` |
| Parallelism | `pthread` work queue |
| Cross-platform | Linux / macOS (via BPF) |

## Author

**ttrossea** — [42 School](https://42.fr)
