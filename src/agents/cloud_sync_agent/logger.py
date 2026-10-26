"""
Logger for Cloud Synchronization Agent.
"""

import logging

def get_cloud_sync_logger() -> logging.Logger:
    logger = logging.getLogger("CloudSyncAgent")
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter("[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger
