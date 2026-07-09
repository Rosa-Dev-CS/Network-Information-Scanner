"""
ARP Scanning module for Network Information Scanner.
Manages sending ARP packets, measuring latency, retrieving TTL values
for OS heuristics, and updating progress.
"""

import sys
import time
import logging
import ipaddress
from typing import List, Dict, Any

# Suppress Scapy runtime logging warnings before importing Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
try:
    from scapy.all import ARP, Ether, srp, IP, ICMP, sr1
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from hostname import resolve_hostname
from utils import lookup_vendor, detect_os_by_ttl, load_oui_database

logger = logging.getLogger("NetworkScanner")


def get_target_ips(target: str) -> List[str]:
    """
    Generates a list of target IP addresses from a target string (single IP or subnet CIDR).

    Args:
        target (str): The target network range or single IP.

    Returns:
        List[str]: List of IP address strings to scan.
    """
    if "/" not in target:
        return [target]

    try:
        net = ipaddress.IPv4Network(target, strict=False)
        if net.num_addresses <= 2:
            return [str(ip) for ip in net]
        else:
            # For standard networks, skip network and broadcast address
            return [str(ip) for ip in net.hosts()]
    except Exception as e:
        logger.error(f"Failed to expand target IPs for {target}: {e}")
        return []


def print_progress_bar(iteration: int, total: int, prefix: str = 'Progress', suffix: str = 'Complete', length: int = 40):
    """
    Prints a terminal progress bar.

    Args:
        iteration (int): Current iteration.
        total (int): Total iterations.
        prefix (str): Prefix string.
        suffix (str): Suffix string.
        length (int): Character length of the progress bar.
    """
    percent = f"{100 * (iteration / float(total)):.1f}"
    filled_length = int(length * iteration // total)
    bar = '█' * filled_length + '-' * (length - filled_length)
    sys.stdout.write(f'\r{prefix}: |{bar}| {percent}% {suffix}')
    sys.stdout.flush()
    if iteration == total:
        print()


def ping_for_ttl(ip_address: str, timeout: float = 0.5) -> tuple:
    """
    Sends an ICMP Echo Request to get TTL and compute response time (RTT).

    Args:
        ip_address (str): The IP to ping.
        timeout (float): Max wait time.

    Returns:
        tuple: (ttl, rtt_ms) or (None, None) if host doesn't respond.
    """
    if not SCAPY_AVAILABLE:
        return None, None

    try:
        packet = IP(dst=ip_address)/ICMP()
        start_time = time.time()
        reply = sr1(packet, timeout=timeout, verbose=False)
        duration_ms = (time.time() - start_time) * 1000.0

        if reply and reply.haslayer(IP):
            return reply.getlayer(IP).ttl, duration_ms
    except Exception as e:
        logger.debug(f"ICMP ping to {ip_address} failed: {e}")

    return None, None


def scan_network(target: str, verbose: bool = False, quiet: bool = False, batch_size: int = 32) -> List[Dict[str, Any]]:
    """
    Performs an ARP scan on target IP addresses, resolves hostnames, looks up vendor
    information, gathers OS heuristics, and measures round-trip time.

    Args:
        target (str): Target single IP or subnet CIDR.
        verbose (bool): Prints debugging and detailed execution logs to stdout.
        quiet (bool): Suppresses all terminal progress bars and status updates.
        batch_size (int): Size of IP batches scanned concurrently.

    Returns:
        List[Dict[str, Any]]: Sorted list of discovered device dictionaries.
    """
    if not SCAPY_AVAILABLE:
        logger.error("Scapy library is not installed or available.")
        return []

    target_ips = get_target_ips(target)
    total_ips = len(target_ips)

    if total_ips == 0:
        logger.warning(f"No valid target IP addresses derived from target '{target}'")
        return []

    logger.info(f"Starting ARP scan on target: {target} ({total_ips} total IPs)")
    if verbose and not quiet:
        print(f"[INFO] Expanded target: {target} into {total_ips} target IP(s).")

    oui_db = load_oui_database()
    discovered_devices = {}

    # Split target_ips into batches for concurrent execution using Scapy's srp
    batches = [target_ips[i:i + batch_size] for i in range(0, total_ips, batch_size)]
    total_batches = len(batches)

    if not quiet:
        print_progress_bar(0, total_batches, prefix='Scanning Network', suffix='Complete', length=30)

    for idx, batch in enumerate(batches):
        if verbose and not quiet:
            # Clear line and print info
            sys.stdout.write(f"\r[INFO] Scanning batch {idx + 1}/{total_batches} ({len(batch)} IPs)...\n")
            sys.stdout.flush()

        try:
            # Craft ARP Request
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp = ARP(pdst=batch)
            packet = ether/arp

            # Send and receive at Layer 2
            # timeout of 1.5s ensures we wait enough for local devices
            start_time = time.time()
            ans, _ = srp(packet, timeout=1.5, verbose=False, retry=1)

            for sent, received in ans:
                ip_addr = received.psrc
                mac_addr = received.hwsrc
                # ARP RTT calculation
                rtt_ms = (received.time - sent.sent_time) * 1000.0

                if ip_addr not in discovered_devices:
                    discovered_devices[ip_addr] = {
                        "ip": ip_addr,
                        "mac": mac_addr,
                        "vendor": lookup_vendor(mac_addr, oui_db),
                        "hostname": "Unknown",
                        "status": "Online",
                        "ttl": None,
                        "os": "Unknown",
                        "rtt": rtt_ms
                    }
        except Exception as e:
            logger.error(f"Error occurred scanning batch {idx + 1}: {e}")
            if verbose and not quiet:
                print(f"\n[ERROR] Scanning batch {idx + 1} failed: {e}")

        if not quiet:
            print_progress_bar(idx + 1, total_batches, prefix='Scanning Network', suffix='Complete', length=30)

    # Secondary lookup phase (resolving hostnames & pings for TTL OS heuristics)
    active_devices = list(discovered_devices.values())
    total_active = len(active_devices)

    if total_active > 0:
        logger.info(f"Discovered {total_active} active devices. Starting detail lookup phase...")
        if verbose and not quiet:
            print(f"[INFO] Discovered {total_active} active devices. Resolving hostnames and OS details...")

        for idx, device in enumerate(active_devices):
            ip = device["ip"]
            # Resolve Hostname
            device["hostname"] = resolve_hostname(ip)

            # Retrieve TTL and measure RTT via ICMP
            ttl, icmp_rtt = ping_for_ttl(ip)
            if ttl is not None:
                device["ttl"] = ttl
                device["os"] = detect_os_by_ttl(ttl)
                # Overwrite/update RTT with ICMP if successful (usually more standard for OS representation)
                device["rtt"] = icmp_rtt

    # Sort devices by IP address (correct mathematical sort using ipaddress.IPv4Address)
    try:
        active_devices.sort(key=lambda x: ipaddress.IPv4Address(x["ip"]))
    except Exception as e:
        logger.warning(f"Error sorting devices: {e}. Falling back to default order.")

    logger.info(f"Scan finished. Discovered {len(active_devices)} hosts.")
    return active_devices
