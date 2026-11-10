"""Stdlib logging wired to a rotating file in the app data dir."""
from __future__ import annotations
import logging, sys
from pathlib import Path
def get_logger(name: str = "spider_web") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
        logger.addHandler(h)
    return logger
