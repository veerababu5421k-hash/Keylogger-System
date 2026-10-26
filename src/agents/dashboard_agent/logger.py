"""
Dedicated Logger for Dashboard Agent.
"""

import logging

def get_dashboard_logger():
    logger = logging.getLogger("DashboardAgent")
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter('[%(asctime)s] [DashboardAgent] [%(levelname)s] %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger
