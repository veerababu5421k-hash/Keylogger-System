"""
Dedicated Logger for Process Monitor Agent.
"""

import logging

def get_process_logger():
    logger = logging.getLogger("ProcessAgent")
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter('[%(asctime)s] [ProcessAgent] [%(levelname)s] %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger
