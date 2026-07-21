# Network Information Scanner
## 📌 Features

### Network Scanning

- Scan a single IP address
- Scan an entire subnet (CIDR notation)
- ARP-based host discovery
- Detect only active devices
- Progress indicator during scanning

---

### Device Information

Displays the following information for every discovered device:

- IP Address
- MAC Address
- Hostname
- MAC Vendor / Manufacturer
- Device Status
- Estimated Operating System (TTL Heuristic)
- Approximate Response Time

---

### Export Results

Export scan results to:

- CSV
- JSON

Results are automatically saved inside the **output/** directory.

---

### Logging

Logs are automatically stored inside the **logs/** directory.

Logged Events:

- Scan Started
- Scan Completed
- Invalid Input
- Export Success
- Errors
- Exceptions

---

### Command Line Interface

Colorful CLI powered by **Colorama**

Includes:

- ASCII Banner
- Colored Status Messages

```
[INFO]
[SUCCESS]
[WARNING]
[ERROR]
```

---

### Error Handling

Gracefully handles:

- Invalid IP Addresses
- Invalid Subnets
- Network Errors
- Permission Errors
- Keyboard Interrupt (Ctrl+C)
- Unexpected Exceptions

---

### Bonus Features

- Response Time Measurement
- Operating System Guess (TTL)
- Sort Devices by IP
- Scan Percentage
- Quiet Mode
- Verbose Mode

---

# 🛠 Technologies Used

- Python 3.12+
- Scapy
- Socket
- Colorama
- Logging
- JSON
- CSV
- ipaddress
- argparse
- datetime
- os

---

# 📂 Project Structure

```

Network-Information-Scanner/

├── scanner.py
├── arp_scanner.py
├── hostname.py
├── exporter.py
├── logger.py
├── validator.py
├── utils.py
├── requirements.txt
├── README.md
├── LICENSE
├── output/
├── logs/
└── assets/

```

---

# 🚀 Installation

Clone the repository

```bash
git clone https://github.com/yourusername/Network-Information-Scanner.git

cd Network-Information-Scanner
```

Install dependencies

```bash
pip install -r requirements.txt
```

---

# ▶ Running the Scanner

Scan a single host

```bash
python scanner.py 192.168.1.15
```

Scan a subnet

```bash
python scanner.py 192.168.1.0/24
```

Verbose mode

```bash
python scanner.py 192.168.1.0/24 --verbose
```

Quiet mode

```bash
python scanner.py 192.168.1.0/24 --quiet
```

---

# 💻 Example Output

```

=========================================
NETWORK INFORMATION SCANNER
=========================================

Scanning Network...

Progress : 100%

---------------------------------------------------------------
IP Address      MAC Address        Vendor      Hostname
---------------------------------------------------------------
192.168.1.1     A8:5E:45:XX        TP-Link     Router
192.168.1.10    34:17:EB:XX        Dell        LAPTOP
192.168.1.15    D0:73:D5:XX        Samsung     Android

---------------------------------------------------------------

Total Active Devices : 3

Scan Duration : 2.4 seconds

Results exported successfully.

```

---

# 📊 Exported Files

```

output/

├── scan_results.csv
└── scan_results.json

```

---

# 📝 Logs

```

logs/

network_scanner.log

```

The application records:

- Scan Start
- Scan Finish
- Errors
- Invalid Inputs
- Export Status

---

# 📷 Screenshots

> Add screenshots here after running the application.

Example:

```

assets/

banner.png

scan.png

export.png

```

---

# 🎯 Learning Objectives

This project demonstrates practical knowledge of:

- Computer Networking
- ARP Protocol
- Local Network Discovery
- Python Socket Programming
- Modular Python Development
- Error Handling
- Logging
- Data Export
- Cybersecurity Fundamentals

---

# 🚀 Future Enhancements

- Multithreaded Scanning
- Port Scanner Integration
- Service Detection
- Network Topology Visualization
- Live Device Monitoring
- GUI Version (Tkinter)
- PDF Report Generation
- SQLite Scan History
- Vendor API Integration
- DNS Enumeration

---

# 📄 License

This project is licensed under the MIT License.

---

# 👩‍💻 Author

Developed by **Rosa**

Cybersecurity Student | Network Security Enthusiast | Python Developer
