"""
Hostname resolution module for Network Information Scanner.
Resolves IP addresses to hostnames using reverse DNS lookups.
"""

import socket
import logging

logger = logging.getLogger("NetworkScanner")


def resolve_hostname(ip_address: str, timeout: float = 1.0) -> str:
    """
    Performs a reverse DNS lookup to resolve the hostname of a given IP address.

    Args:
        ip_address (str): The IP address to resolve.
        timeout (float): The socket timeout in seconds.

    Returns:
        str: Resolved hostname, or "Unknown" if resolution fails.
    """
    # Save the original default timeout
    original_timeout = socket.getdefaulttimeout()
    try:
        # Set a short default timeout to avoid blocking the scan
        socket.setdefaulttimeout(timeout)
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except (socket.herror, socket.gaierror, socket.timeout):
        # DNS lookup failed or timed out
        logger.debug(f"Reverse DNS failed for IP: {ip_address}")
        return "Unknown"
    except Exception as e:
        logger.debug(f"Unexpected error resolving hostname for {ip_address}: {e}")
        return "Unknown"
    finally:
        # Restore the original socket default timeout
        socket.setdefaulttimeout(original_timeout)
