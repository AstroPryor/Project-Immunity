"""
logging_setup.py
Sets up a JSON-line logger for machine-readable logs.
"""

import logging
import os
from pythonjsonlogger import jsonlogger
from logging.handlers import RotatingFileHandler

def setup_logging(logs_dir="logs"):
    os.makedirs(logs_dir, exist_ok=True)
    log_path = os.path.join(logs_dir, "events.jsonl")

    # Root logger config
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # Rotating file handler to avoid unbounded log files
    fh = RotatingFileHandler(log_path, maxBytes=5_000_000, backupCount=5, encoding="utf-8")
    # Format as JSON with timestamp, logger name, level, and message
    fmt = jsonlogger.JsonFormatter('%(asctime)s %(name)s %(levelname)s %(message)s')
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    #Log to console
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s"))
    logger.addHandler(ch)
