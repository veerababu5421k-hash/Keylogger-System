import os
import sys

# Compute the absolute path to the project root directory
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.core.config import load_config
from src.core.logger import setup_logger, get_logger
from src.orchestrator.orchestrator import Orchestrator

def main():
    """
    Main execution routine for Multi-Agent AI Keylogger Detection Platform.
    Loads settings, initializes logging, and boots the Orchestrator.
    """
    config = load_config()
    setup_logger(config)
    logger = get_logger()
    logger.info("Initializing Multi-Agent AI Keylogger Detection Platform...")

    try:
        orchestrator = Orchestrator(config)
        orchestrator.start()
        logger.info("Platform is active. Press Ctrl+C to terminate.")
        while orchestrator.running:
            import time
            time.sleep(1.0)
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received.")
        orchestrator.stop()
    except Exception as error:
        logger.critical("Fatal crash during Orchestrator initialization: %s", error, exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()

