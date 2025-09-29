#!/usr/bin/env python3
"""
network_scanner.py
Single-file network scanner:
 - If given a CIDR and scapy is available (and you run as root), does ARP discovery to find live hosts on the LAN.
 - Then does a threaded TCP connect port scan + simple banner grab for each discovered/target host.
Usage examples:
  sudo python3 network_scanner.py --cidr 192.168.1.0/24 --ports 22-1024
  python3 network_scanner.py --host 10.0.0.5 --ports 80,443,8080
Notes:
 - ARP discovery requires scapy and root privileges.
 - Banner grabbing may hang on some services; timeout is configurable.
"""

import argparse
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress

# Try importing scapy (optional)
try:
    from scapy.all import ARP, Ether, srp, conf  # scapy
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

def arp_discover(cidr, timeout=2):
    """
    Perform ARP discovery on a CIDR network using scapy.
    Returns: list of IP strings that responded.
    Requires scapy and root privileges.
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError("scapy not available")
    conf.verb = 0  # silence scapy
    net = str(cidr)
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=net)
    answered, _ = srp(pkt, timeout=timeout, retry=1)
    hosts = []
    for _, r in answered:
        hosts.append(r.psrc)
    return sorted(hosts, key=lambda ip: tuple(int(x) for x in ip.split('.')))

def parse_ports(port_str):
    """
    Parse ports input like:
      "22,80,443" -> [22,80,443]
      "1-1024"    -> [1..1024]
      "22,80,1000-1010"
    Returns sorted unique list of ints.
    """
    ports = set()
    for part in str(port_str).split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            a, b = part.split('-', 1)
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)

def tcp_banner_grab(host, port, timeout=1.0, recv_bytes=1024):
    """
    Try to connect to host:port and read a small banner (if any).
    Returns tuple (port, True/False, banner-or-error-string)
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                # attempt to receive banner; many services send something
                data = s.recv(recv_bytes)
                banner = data.decode(errors='ignore').strip()
                if banner:
                    return port, True, banner
                else:
                    return port, True, "<no banner>"
            except socket.timeout:
                return port, True, "<open - no banner (timeout)>"
            except Exception as e:
                return port, True, f"<open - recv error: {e}>"
    except ConnectionRefusedError:
        return port, False, "closed"
    except socket.timeout:
        return port, False, "filtered/timeout"
    except OSError as e:
        return port, False, f"error: {e}"
    except Exception as e:
        return port, False, f"error: {e}"

def scan_host_ports(host, ports, workers=100, timeout=1.0):
    """
    Scan list of ports on a single host using a ThreadPoolExecutor.
    Returns: list of (port, is_open(bool), info)
    """
    results = []
    with ThreadPoolExecutor(max_workers=min(workers, max(4, len(ports)))) as ex:
        futures = {ex.submit(tcp_banner_grab, host, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            try:
                res = fut.result()
            except Exception as e:
                res = (futures[fut], False, f"scan-error: {e}")
            results.append(res)
    return sorted(results, key=lambda x: x[0])

def main():
    parser = argparse.ArgumentParser(description="Single-file Python network scanner (ARP discovery + threaded TCP port scan)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--cidr", help="CIDR for local network discovery, e.g. 192.168.1.0/24")
    group.add_argument("--host", help="Single target host IP or hostname, e.g. 10.0.0.5")
    parser.add_argument("--ports", default="1-1024", help="Ports like '22,80,443' or '1-1024' (default 1-1024)")
    parser.add_argument("--workers", type=int, default=200, help="Max parallel threads for scanning")
    parser.add_argument("--timeout", type=float, default=0.8, help="Timeout seconds for connect and banner reads")
    args = parser.parse_args()

    # Build target host list
    targets = []
    if args.cidr:
        try:
            net = ipaddress.ip_network(args.cidr, strict=False)
        except Exception as e:
            print(f"[!] Invalid CIDR: {e}", file=sys.stderr)
            sys.exit(1)

        if not SCAPY_AVAILABLE:
            print("[!] scapy not found: ARP discovery disabled. Install scapy and run as root for ARP scanning.")
            print("[!] Fall back: scanning the network by iterating addresses (slower and may be blocked).")
            # Fallback: treat all usable hosts as targets (but don't ping) — user should be careful
            targets = [str(ip) for ip in net.hosts()]
        else:
            print(f"[+] Performing ARP discovery on {net} (this requires root and scapy)...")
            try:
                hosts = arp_discover(net, timeout=2)
                if not hosts:
                    print("[!] No hosts responded to ARP. The network may be empty or ARP blocked.")
                    # fallback to full list (optional): keep it empty to avoid long scans
                    # targets = [str(ip) for ip in net.hosts()]
                else:
                    targets = hosts
            except PermissionError:
                print("[!] Permission error: you probably need to run as root for ARP discovery.", file=sys.stderr)
                sys.exit(1)
            except Exception as e:
                print(f"[!] ARP discovery failed: {e}", file=sys.stderr)
                sys.exit(1)

    else:  # single host
        targets = [args.host]

    # Parse ports
    ports = parse_ports(args.ports)
    if not ports:
        print("[!] No valid ports specified.", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Targets: {len(targets)} host(s). Ports: {len(ports)}. Workers: {args.workers}. Timeout: {args.timeout}s\n")
    overall = {}
    start_time = time.time()
    for idx, target in enumerate(targets, 1):
        print(f"=== [{idx}/{len(targets)}] Scanning {target} ===")
        try:
            host_res = socket.gethostbyname(target)
        except Exception:
            host_res = target
        results = scan_host_ports(host_res, ports, workers=args.workers, timeout=args.timeout)
        open_ports = [r for r in results if r[1]]
        if open_ports:
            print(f"[+] {len(open_ports)} open ports on {target}:")
            for port, _, info in open_ports:
                print(f"    - {port}: {info}")
        else:
            print(f"[-] No open ports found on {target} (within scanned range/timeouts).")
        overall[target] = results
        print()  # spacer

    elapsed = time.time() - start_time
    print(f"[+] Scan complete in {elapsed:.1f}s. Hosts scanned: {len(targets)}.")
    # Optionally, you could write overall results to a file here.

if __name__ == "__main__":
    main()
