"""
Dedicated Logger for AI Security Analyst Agent.
"""

import logging

def get_ai_analyst_logger():
    logger = logging.getLogger("AIAnalystAgent")
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter('[%(asctime)s] [AIAnalystAgent] [%(levelname)s] %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger
