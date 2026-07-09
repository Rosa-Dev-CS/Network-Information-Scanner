"""
Utility functions for Network Information Scanner.
Includes administrative privilege checking, MAC OUI vendor lookups,
and OS detection based on TTL heuristics.
"""

import os
import sys
import json
import ctypes
import logging

logger = logging.getLogger("NetworkScanner")


def is_admin() -> bool:
    """
    Checks if the script is running with administrative or root privileges.

    Returns:
        bool: True if admin/root, False otherwise.
    """
    try:
        if sys.platform.startswith("win"):
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception as e:
        logger.warning(f"Error checking administrative privileges: {e}")
        return False


def load_oui_database() -> dict:
    """
    Loads the MAC OUI vendor database from the assets folder.

    Returns:
        dict: OUI prefixes mapped to manufacturer names.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    oui_path = os.path.join(script_dir, "assets", "oui_database.json")

    if not os.path.exists(oui_path):
        logger.warning(f"OUI database not found at {oui_path}")
        return {}

    try:
        with open(oui_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to read OUI database: {e}")
        return {}


def lookup_vendor(mac_address: str, oui_db: dict) -> str:
    """
    Looks up the manufacturer/vendor of a MAC address using the OUI database.

    Args:
        mac_address (str): The MAC address (e.g., '00:1c:42:00:00:08').
        oui_db (dict): The loaded OUI database.

    Returns:
        str: Manufacturer name or 'Unknown' if not found.
    """
    if not mac_address:
        return "Unknown"

    # Normalize MAC address format to match database style (e.g. '00:1c:42')
    # Standard format: lowercase, separated by colons
    normalized = mac_address.lower().replace("-", ":")
    prefix = ":".join(normalized.split(":")[:3])

    vendor = oui_db.get(prefix, "Unknown")
    return vendor


def detect_os_by_ttl(ttl: int) -> str:
    """
    Heuristically guesses the target Operating System based on the TTL (Time to Live).

    Common Default TTLs:
    - 64: Linux, macOS, Android, iOS, FreeBSD
    - 128: Windows
    - 255: Cisco router, network hardware, Solaris

    Args:
        ttl (int): The TTL value from a received IP packet.

    Returns:
        str: Estimated Operating System description.
    """
    if ttl is None or ttl < 0:
        return "Unknown"

    # Standard IP network routes might decrement TTL, so we check ranges.
    if ttl <= 64:
        return "Linux/macOS/Android"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 255:
        return "Network Device (Cisco/Unix)"
    else:
        return "Unknown"
