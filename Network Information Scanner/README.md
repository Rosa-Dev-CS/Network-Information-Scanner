# Network Information Scanner

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security Level](https://img.shields.io/badge/Security-Local%20Network-orange.svg)]()

A modular, professional, command-line cybersecurity tool written in Python that scans a local network to discover active devices, identifies manufacturers using a local MAC OUI database, resolves hostnames, estimates operating systems via TTL heuristics, and displays the results in a formatted table.

Developed for security students, network engineers, and system administrators preparing for SOC Analyst, Network Security, or Cybersecurity Internship roles.

---

## Features

- **Flexible Targets**: Scan single IP addresses or full subnets using CIDR notation (e.g., `192.168.1.0/24`).
- **Input Validation**: Strict validation of target IP and subnets using the Python `ipaddress` library to handle invalid inputs gracefully.
- **Fast ARP Discovery**: Utilizes custom batch-based Scapy ARP requests to identify live devices efficiently on local segments.
- **Visual Progress Bar**: Real-time progress updates and percentage counters during network scanning.
- **OUI Manufacturer Lookup**: Matches MAC address prefixes locally against a fast dictionary-based vendor OUI database (`assets/oui_database.json`).
- **Hostname Resolution**: Performs socket reverse DNS queries with configurable timeouts to prevent scanning bottleneck.
- **OS TTL Heuristic**: Guesses operating systems (Windows, Linux/macOS/Android, or Cisco/Network Device) based on standard default TTL response levels.
- **Latency / Response Time**: Computes and logs approximate round-trip times (RTT) in milliseconds for active devices.
- **Multi-Format Exporting**: Supports exporting reports to standard `CSV` or structure-rich `JSON` in the `output/` folder.
- **Logging**: Complete log entries (scan starts, finishes, invalid inputs, export status, permission errors) saved in the `logs/` directory.
- **Robust Exception Handling**: Gracefully intercepts `KeyboardInterrupt` (Ctrl+C), invalid inputs, network unreachable states, and missing administrative privileges.

---

## Technologies Used

- **Core**: Python 3.8+
- **Raw Packet Crafting**: [Scapy](https://scapy.net/)
- **CLI Colorization**: [Colorama](https://pypi.org/project/colorama/)
- **Standard Libraries**: `socket`, `ipaddress`, `argparse`, `json`, `csv`, `logging`, `datetime`, `os`

---

## Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/Network-Information-Scanner.git
cd Network-Information-Scanner
```

### 2. Install Dependencies
You can install the required packages using the `requirements.txt` file.
```bash
pip install -r requirements.txt
```

> [!IMPORTANT]
> **Windows Users**: Scapy relies on `Npcap` or `WinPcap` to perform packet capture and raw injection.
> Please download and install Npcap from the official website: [Npcap Installer](https://npcap.com/#download). During installation, ensure you select "Support raw 802.11 traffic" and "Install Npcap in WinPcap API-compatible Mode".
>
> **Linux/macOS Users**: Scapy requires root privileges to open raw sockets. Ensure you run the scanner using `sudo`.

---

## How to Run

### Command Syntax
```bash
python scanner.py -t <TARGET> [OPTIONS]
```

### Options

| Flag | Long Option | Description |
|---|---|---|
| `-t` | `--target` | **Required**. Single IP address or subnet CIDR notation. |
| `-e` | `--export` | Output report format. Options: `csv` or `json`. |
| `-o` | `--output-name`| Custom name for output file (Default: `scan_results`). |
| `-v` | `--verbose` | Print detailed debug information and batch status logs. |
| `-q` | `--quiet` | Quiet mode. Suppresses banner, progress bar, and logs; outputs results only. |

---

## Example Commands

#### 1. Scan a Single IP
```bash
python scanner.py -t 192.168.1.1
```

#### 2. Scan a Subnet and Export as CSV
```bash
python scanner.py -t 192.168.1.0/24 -e csv
```

#### 3. Scan a Subnet with Verbose Output and Custom JSON Output
```bash
python scanner.py -t 192.168.1.0/24 -e json -o gateway_scan -v
```

#### 4. Run in Quiet Mode
```bash
python scanner.py -t 192.168.1.0/24 -q
```

---

## Example Output

```text
======================================================================
                     NETWORK INFORMATION SCANNER
======================================================================

[INFO] Validating target input...
[SUCCESS] Target validated successfully as a SUBNET.
[INFO] Scanning target network range: 192.168.1.0/24
Scanning Network: |██████████████████████████████| 100.0% Complete

[SUCCESS] Discovered active devices:
---------------------------------------------------------------------------------------------------------
IP Address       MAC Address          Vendor             Hostname           Estimated OS           RTT (ms)  
---------------------------------------------------------------------------------------------------------
192.168.1.1      00:08:5D:1A:2B:3C    Hewlett Packard    Router.local       Network Device         1.45      
192.168.1.10     34:17:EB:4D:5E:6F    Dell               DESKTOP-DELL       Windows                2.84      
192.168.1.15     70:CD:0D:8F:90:AB    Samsung            Galaxy-S21         Linux/macOS/Android    12.30     
---------------------------------------------------------------------------------------------------------

====================================================================== 
                            SCAN SUMMARY
====================================================================== 
Total IPs Scanned : 254
Total Active Hosts: 3
Scan Start Time   : 2026-07-10 01:15:30
Scan End Time     : 2026-07-10 01:15:42
Scan Duration     : 12.12 seconds
====================================================================== 
```

---

## Project Structure

```text
Network-Information-Scanner/
│
├── scanner.py          # CLI entry point, parses arguments, and prints tables
├── arp_scanner.py      # Core ARP batch scanning and ICMP validation routines
├── hostname.py         # Performs thread-safe reverse DNS hostname lookups
├── exporter.py         # Handles formatting and writing to CSV & JSON reports
├── logger.py           # Sets up file logging logs/scanner.log
├── validator.py        # Validates target IPv4 addresses and network blocks
├── utils.py            # OS detection, privilege checks, and OUI database loader
├── requirements.txt    # Declares external packages: scapy and colorama
├── LICENSE             # MIT License
├── README.md           # Professional project presentation
│
├── assets/
│   └── oui_database.json  # Local MAC OUI manufacturer mapping database
├── logs/
│   └── scanner.log        # Automatically generated audit logs
└── output/
    └── scan_results.csv   # Target exports directory
```

---

## Future Enhancements

1. **Port Scanning**: Add simple TCP SYN scanning for open ports on discovered devices.
2. **Multi-threading DNS**: Speed up DNS hostname resolution for massive networks using a thread pool.
3. **IPv6 Support**: Expand packet structures to support IPv6 NDP (Neighbor Discovery Protocol).
4. **Web UI Interface**: Create a dashboard using Flask or FastAPI for remote network scanning results visualization.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
