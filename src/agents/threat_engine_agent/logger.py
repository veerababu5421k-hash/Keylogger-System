"""
Dedicated Logger for Threat Engine Agent.
"""

import logging

def get_threat_engine_logger():
    logger = logging.getLogger("ThreatEngineAgent")
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter('[%(asctime)s] [ThreatEngineAgent] [%(levelname)s] %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger
