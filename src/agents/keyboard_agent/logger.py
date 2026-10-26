"""
Dedicated Logger for Keyboard Activity Agent.
"""

import logging

def get_keyboard_logger():
    logger = logging.getLogger("KeyboardAgent")
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter('[%(asctime)s] [KeyboardAgent] [%(levelname)s] %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger
