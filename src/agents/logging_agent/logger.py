"""
Dedicated Logger for Logging Agent.
"""

import logging

def get_logging_agent_logger():
    logger = logging.getLogger("LoggingAgentInternal")
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter('[%(asctime)s] [LoggingAgent] [%(levelname)s] %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger
