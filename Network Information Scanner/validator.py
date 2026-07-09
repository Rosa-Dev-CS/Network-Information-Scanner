"""
Validator module for Network Information Scanner.
Provides functions to validate single IP addresses and subnets.
"""

import ipaddress
import logging

logger = logging.getLogger("NetworkScanner")


def is_valid_ip(ip_str: str) -> bool:
    """
    Validates if a string is a valid IPv4 address.

    Args:
        ip_str (str): The IP address string to validate.

    Returns:
        bool: True if valid, False otherwise.
    """
    try:
        ipaddress.IPv4Address(ip_str.strip())
        return True
    except ipaddress.AddressValueError:
        return False


def is_valid_subnet(subnet_str: str) -> bool:
    """
    Validates if a string is a valid IPv4 network subnet (CIDR notation).

    Args:
        subnet_str (str): The subnet CIDR string to validate (e.g. 192.168.1.0/24).

    Returns:
        bool: True if valid, False otherwise.
    """
    try:
        ipaddress.IPv4Network(subnet_str.strip(), strict=False)
        return True
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        return False


def parse_and_validate_target(target_str: str) -> tuple[bool, str, str]:
    """
    Parses the input target string and identifies if it is a valid single IP or a valid subnet CIDR.

    Args:
        target_str (str): The input target string from user.

    Returns:
        tuple[bool, str, str]: (is_valid, target_type, normalized_target)
            is_valid: Boolean indicating whether target is valid.
            target_type: "ip", "subnet", or "invalid".
            normalized_target: The cleaned up target string, or an error message if invalid.
    """
    cleaned_target = target_str.strip()
    if not cleaned_target:
        return False, "invalid", "Empty input provided."

    # Check for single IP address
    if "/" not in cleaned_target:
        if is_valid_ip(cleaned_target):
            return True, "ip", cleaned_target
        else:
            return False, "invalid", f"'{cleaned_target}' is not a valid IPv4 address."

    # Check for subnet network address
    else:
        if is_valid_subnet(cleaned_target):
            # Normalize the network CIDR (strict=False ensures host bits are zeroed out if specified)
            net = ipaddress.IPv4Network(cleaned_target, strict=False)
            return True, "subnet", str(net)
        else:
            return False, "invalid", f"'{cleaned_target}' is not a valid IPv4 subnet CIDR."
