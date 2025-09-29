# NETWORK-SCANNING-USING-PYTHON
Network scanning is discovering hosts, open ports, and services on a network.
# Network Scanner (single-file Python)

Lightweight single-file network scanner that optionally does ARP discovery (local LAN) and threaded TCP connect port scanning with simple banner grabbing. **Only scan networks you own or are authorized to test.**

## Features
- ARP discovery on a CIDR (requires `scapy` + root/admin).
- Threaded TCP port scanning and basic banner grabbing.
- Single executable file: `network_scanner.py`.

## Requirements
- Python 3.7+
- Optional: `scapy` for `--cidr` ARP discovery  
  Install: `pip3 install scapy`

## Quick usage
```bash
# Scan single host (default ports 1-1024)
python3 network_scanner.py --host 10.0.0.5

# Scan specific ports
python3 network_scanner.py --host 10.0.0.5 --ports 22,80,443

# Scan CIDR using ARP discovery (requires scapy and root)
sudo python3 network_scanner.py --cidr 192.168.1.0/24 --ports 22,80,443

# Increase threads (be careful)
python3 network_scanner.py --host 10.0.0.5 --ports 1-1024 --workers 400 --timeout 0.5

