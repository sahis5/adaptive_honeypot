# backend/logging_config.py
import logging, os
from logging.handlers import RotatingFileHandler
from .config import LOG_PATH, LOG_LEVEL
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, "logs")


def setup_logging(app_name="adaptive_honeypot"):
    os.makedirs(LOG_PATH, exist_ok=True)
    log_file = os.path.join(LOG_PATH, f"{app_name}.log")

    root = logging.getLogger()
    root.setLevel(getattr(logging, LOG_LEVEL.upper(), logging.INFO))

    # console handler (useful when running in Docker / dev)
    ch = logging.StreamHandler()
    ch.setLevel(root.level)
    fmt = logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s')
    ch.setFormatter(fmt)
    root.addHandler(ch)

    # rotating file handler
    fh = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8')
    fh.setLevel(root.level)
    fh.setFormatter(fmt)
    root.addHandler(fh)

    return log_file
