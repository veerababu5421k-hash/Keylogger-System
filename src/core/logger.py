import os
import json
import logging
from datetime import datetime

class JsonFormatter(logging.Formatter):
    """
    Custom logging formatter that outputs log records as single-line JSON strings.
    """
    def format(self, record):
        # Create a dictionary representing the log record structure
        log_record = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage()
        }
        
        # If additional dictionaries are passed via 'extra', merge them into the JSON
        if hasattr(record, "extra_data"):
            log_record.update(record.extra_data)
            
        # Convert dictionary to JSON string
        return json.dumps(log_record)

def setup_logger(config):
    """
    Configures the global logging system using settings loaded from configuration.
    Creates logs directory if it does not exist.
    """
    log_config = config.get("logging", {})
    
    # Read log file paths and logging levels from configuration
    agent_log_path = log_config.get("log_file", "logs/agent.log")
    alert_log_path = log_config.get("alert_file", "logs/alerts.json")
    
    # Resolve log levels string to logging library constants (default to INFO)
    console_level_str = log_config.get("console_level", "INFO").upper()
    file_level_str = log_config.get("file_level", "INFO").upper()
    
    console_level = getattr(logging, console_level_str, logging.INFO)
    file_level = getattr(logging, file_level_str, logging.INFO)

    # Ensure the parent directory for the log files exists
    for path in [agent_log_path, alert_log_path]:
        dir_name = os.path.dirname(path)
        if dir_name and not os.path.exists(dir_name):
            os.makedirs(dir_name, exist_ok=True)

    # ----------------------------------------------------
    # 1. Configure the Operational Logger (General Logs)
    # ----------------------------------------------------
    op_logger = logging.getLogger("KeyShield")
    op_logger.setLevel(logging.DEBUG)  # Capture all levels at root logger
    op_logger.propagate = False         # Prevent sending logs to default root handlers

    # Clear existing handlers to avoid duplicates during reloads
    if op_logger.hasHandlers():
        op_logger.handlers.clear()

    # Standard human-readable format for system administrators
    readable_formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Console Handler (writes to command line screen)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(console_level)
    console_handler.setFormatter(readable_formatter)
    op_logger.addHandler(console_handler)

    # File Handler (writes text logs to agent.log)
    file_handler = logging.FileHandler(agent_log_path, encoding='utf-8')
    file_handler.setLevel(file_level)
    file_handler.setFormatter(readable_formatter)
    op_logger.addHandler(file_handler)

    # ----------------------------------------------------
    # 2. Configure the Security Alert Logger (JSON Alerts)
    # ----------------------------------------------------
    alert_logger = logging.getLogger("KeyShieldAlert")
    alert_logger.setLevel(logging.INFO)
    alert_logger.propagate = False

    if alert_logger.hasHandlers():
        alert_logger.handlers.clear()

    # File Handler using our custom JSON Formatter
    alert_file_handler = logging.FileHandler(alert_log_path, encoding='utf-8')
    alert_file_handler.setLevel(logging.INFO)
    alert_file_handler.setFormatter(JsonFormatter())
    alert_logger.addHandler(alert_file_handler)

    op_logger.info("Logging system initialized. Console level: %s, File level: %s", console_level_str, file_level_str)
    op_logger.info("Operational logs written to: %s", agent_log_path)
    op_logger.info("Security alert logs written to: %s", alert_log_path)

def get_logger():
    """
    Helper to get the operational logger instance.
    """
    return logging.getLogger("KeyShield")

def log_security_alert(module_name, message, risk_score, pid=None, extra_info=None):
    """
    Helper to generate a structured JSON security alert.
    
    Args:
        module_name (str): The name of the monitor (e.g., 'keyboard', 'process')
        message (str): A description of the suspicious behavior
        risk_score (float): Calculated risk score (0.0 to 100.0)
        pid (int, optional): Process ID responsible for the event
        extra_info (dict, optional): Any extra context (IPs, files, command lines)
    """
    alert_logger = logging.getLogger("KeyShieldAlert")
    op_logger = logging.getLogger("KeyShield")

    # Construct the telemetry dictionary
    extra_data = {
        "module": module_name,
        "risk_score": risk_score,
        "pid": pid
    }
    
    # Merge additional metrics if provided
    if extra_info:
        extra_data.update(extra_info)

    # Log using python's 'extra' argument to pass the dictionary to the formatter
    alert_logger.info(message, extra={"extra_data": extra_data})
    
    # Also log a clean notification to the console operational logger
    op_logger.warning("ALERT [%s] (Risk: %.1f, PID: %s): %s", module_name.upper(), risk_score, pid or "N/A", message)

if __name__ == "__main__":
    # Test block to verify logger functions stand-alone
    print("Testing Logging Module...")
    from config import load_config
    config = load_config()
    setup_logger(config)
    
    logger = get_logger()
    logger.info("This is a standard information message.")
    logger.debug("This is a debug message (will show if console level is DEBUG).")
    
    log_security_alert(
        module_name="test_monitor",
        message="Suspicious activity simulation",
        risk_score=75.5,
        pid=9999,
        extra_info={"target_file": "/etc/passwd", "connection_ip": "1.2.3.4"}
    )
    print("Logging Module Test Complete. Please check 'logs/agent.log' and 'logs/alerts.json'.")
