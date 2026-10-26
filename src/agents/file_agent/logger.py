"""
Dedicated Logger for File Activity Agent.
"""

import logging

def get_file_logger():
    logger = logging.getLogger("FileAgent")
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter('[%(asctime)s] [FileAgent] [%(levelname)s] %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger
