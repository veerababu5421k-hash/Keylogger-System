"""
Dedicated Logger for Cron Automation Agent.
"""

import logging

def get_cron_logger():
    logger = logging.getLogger("CronAgent")
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter('[%(asctime)s] [CronAgent] [%(levelname)s] %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger
