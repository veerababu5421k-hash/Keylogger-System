"""
Dedicated Logger for Network Monitor Agent.
"""

import logging

def get_network_logger():
    logger = logging.getLogger("NetworkAgent")
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter('[%(asctime)s] [NetworkAgent] [%(levelname)s] %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger
