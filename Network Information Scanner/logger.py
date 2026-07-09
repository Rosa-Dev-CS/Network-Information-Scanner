"""
Logging module for Network Information Scanner.
Sets up the logger and ensures the logs directory exists.
"""

import logging
import os
from datetime import datetime


def setup_logger(log_dir: str = "logs", log_filename: str = "scanner.log") -> logging.Logger:
    """
    Configures and returns the main application logger.
    Writes logs to a file within the specified directory.

    Args:
        log_dir (str): The folder where log files will be stored.
        log_filename (str): The name of the log file.

    Returns:
        logging.Logger: Configured Logger instance.
    """
    # Ensure log directory exists
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    log_path = os.path.join(log_dir, log_filename)

    logger = logging.getLogger("NetworkScanner")
    logger.setLevel(logging.DEBUG)

    # Prevent duplicate handlers if setup_logger is called multiple times
    if not logger.handlers:
        # File handler (logs all debug and higher events)
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)

        # Formatter
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger
