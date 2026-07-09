"""
Exporter module for Network Information Scanner.
Exports discovered active network devices to CSV and JSON formats.
"""

import os
import csv
import json
import logging
from typing import List, Dict, Any

logger = logging.getLogger("NetworkScanner")


def ensure_output_dir(output_dir: str = "output") -> str:
    """
    Ensures that the output directory exists.

    Args:
        output_dir (str): Name of the output directory.

    Returns:
        str: Absolute path of the output directory.
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        logger.debug(f"Created output directory: {output_dir}")
    return output_dir


def export_to_csv(devices: List[Dict[str, Any]], filename: str, output_dir: str = "output") -> str:
    """
    Exports target device scan results to a CSV file.

    Args:
        devices (List[Dict[str, Any]]): List of device info dictionaries.
        filename (str): The name of the file to save (without directory prefix).
        output_dir (str): Output folder path.

    Returns:
        str: The full path to the exported CSV file.
    """
    ensure_output_dir(output_dir)
    file_path = os.path.join(output_dir, filename)

    if not file_path.endswith(".csv"):
        file_path += ".csv"

    # Define headers
    headers = ["IP Address", "MAC Address", "Vendor", "Hostname", "Status", "TTL Heuristic", "Estimated OS", "Response Time (ms)"]

    try:
        with open(file_path, mode="w", newline="", encoding="utf-8") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(headers)

            for d in devices:
                writer.writerow([
                    d.get("ip", ""),
                    d.get("mac", ""),
                    d.get("vendor", "Unknown"),
                    d.get("hostname", "Unknown"),
                    d.get("status", "Online"),
                    d.get("ttl", "N/A"),
                    d.get("os", "Unknown"),
                    f"{d.get('rtt', 0.0):.2f}" if d.get("rtt") is not None else "N/A"
                ])

        logger.info(f"Exported scan results to CSV successfully: {file_path}")
        return file_path
    except Exception as e:
        logger.error(f"Failed to export scan results to CSV: {e}")
        raise e


def export_to_json(devices: List[Dict[str, Any]], filename: str, output_dir: str = "output") -> str:
    """
    Exports target device scan results to a JSON file.

    Args:
        devices (List[Dict[str, Any]]): List of device info dictionaries.
        filename (str): The name of the file to save (without directory prefix).
        output_dir (str): Output folder path.

    Returns:
        str: The full path to the exported JSON file.
    """
    ensure_output_dir(output_dir)
    file_path = os.path.join(output_dir, filename)

    if not file_path.endswith(".json"):
        file_path += ".json"

    try:
        with open(file_path, "w", encoding="utf-8") as json_file:
            json.dump(devices, json_file, indent=4)

        logger.info(f"Exported scan results to JSON successfully: {file_path}")
        return file_path
    except Exception as e:
        logger.error(f"Failed to export scan results to JSON: {e}")
        raise e
