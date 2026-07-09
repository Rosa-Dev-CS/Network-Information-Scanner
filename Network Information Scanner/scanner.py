"""
Network Information Scanner
A professional, modular cybersecurity tool to scan a local network and discover active devices.
Main CLI script that coordinates inputs, validates, runs scans, prints tables, and handles errors.
"""

import os
import sys
import argparse
from datetime import datetime
import logging

from colorama import Fore, Back, Style, init

# Suppress Scapy runtime logging warnings before importing Scapy modules
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import validator
from logger import setup_logger
from utils import is_admin
import arp_scanner
import exporter

# Initialize colorama for colored terminal outputs
init(autoreset=True)

# Application Logger
logger = setup_logger()


def display_banner():
    """
    Displays the colorful ASCII header banner for the scanner.
    """
    banner_text = f"""
{Fore.CYAN}{Style.BRIGHT}======================================================================
                     NETWORK INFORMATION SCANNER
======================================================================{Style.RESET_ALL}
    """
    print(banner_text)


def print_status(message: str, status_type: str = "info"):
    """
    Helper function to print formatted and colored status messages to stdout.

    Args:
        message (str): The text message to output.
        status_type (str): The level category: "info", "success", "warning", or "error".
    """
    if status_type == "info":
        print(f"{Fore.BLUE}{Style.BRIGHT}[INFO]{Style.RESET_ALL} {message}")
    elif status_type == "success":
        print(f"{Fore.GREEN}{Style.BRIGHT}[SUCCESS]{Style.RESET_ALL} {message}")
    elif status_type == "warning":
        print(f"{Fore.YELLOW}{Style.BRIGHT}[WARNING]{Style.RESET_ALL} {message}")
    elif status_type == "error":
        print(f"{Fore.RED}{Style.BRIGHT}[ERROR]{Style.RESET_ALL} {message}")


def display_devices_table(devices: list):
    """
    Prints a formatted, PEP-8 and color-coded table of discovered devices.

    Args:
        devices (list): List of discovered device dictionaries.
    """
    # Columns: IP Address, MAC Address, Vendor, Hostname, Estimated OS, Latency (RTT)
    col_format = "{:<16} {:<20} {:<18} {:<18} {:<22} {:<10}"
    divider = "-" * 105

    print(divider)
    print(Fore.YELLOW + Style.BRIGHT + col_format.format(
        "IP Address", "MAC Address", "Vendor", "Hostname", "Estimated OS", "RTT (ms)"
    ))
    print(divider)

    for dev in devices:
        rtt_str = f"{dev.get('rtt', 0.0):.2f}" if dev.get("rtt") is not None else "N/A"
        print(col_format.format(
            dev.get("ip", ""),
            dev.get("mac", ""),
            dev.get("vendor", "Unknown"),
            dev.get("hostname", "Unknown"),
            dev.get("os", "Unknown"),
            rtt_str
        ))
    print(divider)


def main():
    """
    Main function of the scanner. Parses arguments, handles validations,
    executes ARP scan, logs metrics, and outputs results.
    """
    parser = argparse.ArgumentParser(
        description="Network Information Scanner - A professional CLI local network discovery tool.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target IP address or Subnet CIDR (e.g. 192.168.1.1 or 192.168.1.0/24)"
    )
    parser.add_argument(
        "-e", "--export",
        choices=["csv", "json"],
        help="Export target format for scan results (csv or json)"
    )
    parser.add_argument(
        "-o", "--output-name",
        default="scan_results",
        help="Custom name for the exported file (without file extension)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable detailed execution logging and verbose scanner outputs"
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Run scanner in quiet mode (suppress banner, progress, and logs; print table only)"
    )

    args = parser.parse_args()

    # Determine logging level based on verbose option
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # 1. Print Banner (unless quiet mode)
    if not args.quiet:
        display_banner()

    # 2. Setup environment checks
    logger.info("Initializing scanner verification checks...")

    # 3. Check for Administrative / Root privileges
    if not is_admin():
        msg = "Administrative (Root/Administrator) privileges are required to send raw network packets (Scapy ARP requests)."
        logger.error(f"Permission Error: {msg}")
        print_status(msg, "error")
        print_status("Please run the command shell as Administrator (Windows) or using sudo (Linux/macOS).", "info")
        sys.exit(1)

    # 4. Target Validation
    if not args.quiet:
        print_status("Validating target input...", "info")

    is_valid, target_type, validation_res = validator.parse_and_validate_target(args.target)
    if not is_valid:
        logger.warning(f"Invalid scan target submitted: '{args.target}' - {validation_res}")
        print_status(validation_res, "error")
        sys.exit(1)

    logger.info(f"Target validation success: IP/Range={args.target}, Type={target_type}")
    if not args.quiet:
        print_status(f"Target validated successfully as a {target_type.upper()}.", "success")

    # Expand target IPs to log count
    expanded_ips = arp_scanner.get_target_ips(validation_res)
    total_ips_count = len(expanded_ips)

    # 5. Scan network
    start_time = datetime.now()
    logger.info(f"Scan initiated for target: {validation_res} containing {total_ips_count} IP(s)")
    if not args.quiet:
        print_status(f"Scanning target network range: {validation_res}", "info")

    try:
        active_devices = arp_scanner.scan_network(
            validation_res,
            verbose=args.verbose,
            quiet=args.quiet
        )
    except KeyboardInterrupt:
        logger.warning("Scan aborted by the user (KeyboardInterrupt).")
        print()  # print newline after progress bar
        print_status("Scan aborted by user. Exiting...", "warning")
        sys.exit(0)
    except PermissionError as pe:
        logger.error(f"PermissionError during packet operations: {pe}")
        print_status(f"Permission error occurred: {pe}", "error")
        sys.exit(1)
    except OSError as oe:
        # Check for Network Unreachable or Interface issues
        logger.error(f"OS/Network interface error: {oe}")
        print_status(f"Network error: {oe}. Please verify your network connection and interfaces.", "error")
        sys.exit(1)
    except Exception as ex:
        logger.critical(f"Unexpected exception during network scan: {ex}", exc_info=True)
        print_status(f"An unexpected error occurred: {ex}", "error")
        sys.exit(1)

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    logger.info(f"Scan finalized in {duration:.2f} seconds. Discovered {len(active_devices)} hosts.")

    # 6. Display results
    if not args.quiet:
        print()
        print_status(f"Discovered active devices:", "success")

    display_devices_table(active_devices)

    # 7. Print Scan Summary
    if not args.quiet:
        print("\n====================================================================== ")
        print("                            SCAN SUMMARY")
        print("====================================================================== ")
        print(f"Total IPs Scanned : {total_ips_count}")
        print(f"Total Active Hosts: {len(active_devices)}")
        print(f"Scan Start Time   : {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Scan End Time     : {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Scan Duration     : {duration:.2f} seconds")
        print("====================================================================== ")

    # 8. Export Results
    if args.export and len(active_devices) > 0:
        if not args.quiet:
            print_status(f"Exporting results to {args.export.upper()}...", "info")

        try:
            filename = args.output_name
            if args.export == "csv":
                exported_path = exporter.export_to_csv(active_devices, filename)
            else:
                exported_path = exporter.export_to_json(active_devices, filename)

            msg = f"Results exported successfully to {exported_path}"
            logger.info(f"Export success: {exported_path}")
            if not args.quiet:
                print_status(msg, "success")
            else:
                # In quiet mode, if export is requested, still display the path of the exported file
                print(f"Results exported: {exported_path}")

        except Exception as e:
            logger.error(f"Failed to export findings: {e}")
            print_status(f"Export failed: {e}", "error")
    elif args.export and len(active_devices) == 0:
        if not args.quiet:
            print_status("No active devices discovered. Skipping export.", "warning")
        logger.info("No active devices discovered. Skipping export.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[WARNING] Execution interrupted by KeyboardInterrupt.")
        sys.exit(0)
