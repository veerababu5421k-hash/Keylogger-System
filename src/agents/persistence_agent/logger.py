"""
Dedicated Logger for Persistence Monitor Agent.
"""

import logging

def get_persistence_logger():
    logger = logging.getLogger("PersistenceAgent")
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter('[%(asctime)s] [PersistenceAgent] [%(levelname)s] %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger
