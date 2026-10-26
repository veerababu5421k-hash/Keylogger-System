import os
import yaml

# Hardcoded fallback configuration to ensure the agent runs even if the yaml file is deleted or corrupt.
DEFAULT_CONFIG = {
    "agent": {
        "node_name": "secureshield-fallback-agent",
        "tick_interval": 5.0
    },
    "logging": {
        "log_file": "logs/agent.log",
        "alert_file": "logs/alerts.json",
        "console_level": "INFO",
        "file_level": "INFO"
    },
    "monitors": {
        "process": {
            "enabled": True,
            "scan_interval": 2.0,
            "cpu_threshold": 80.0,
            "memory_threshold": 15.0,
            "whitelist_pids": [],
            "whitelist_names": ["systemd", "bash", "sshd"]
        },
        "keyboard": {
            "enabled": True,
            "device_path": "/dev/input",
            "keystroke_rate_threshold": 20.0
        },
        "persistence": {
            "enabled": True,
            "scan_interval": 10.0,
            "monitored_paths": ["/etc/systemd/system", "/etc/init.d"]
        },
        "file": {
            "enabled": True,
            "monitored_files": ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]
        },
        "network": {
            "enabled": True,
            "scan_interval": 3.0,
            "whitelist_ips": ["127.0.0.1", "0.0.0.0"]
        }
    },
    "threat_engine": {
        "alert_risk_threshold": 50.0
    },
    "ai_analyst": {
        "enabled": False,
        "provider": "gemini",
        "model_name": "gemini-2.5-flash",
        "ollama_url": "http://localhost:11434",
        "analysis_interval": 60.0
    }
}

def load_config(config_path="config/agent.yaml"):
    """
    Loads and parses the YAML configuration file.
    Falls back to DEFAULT_CONFIG if the file is not found or is corrupt.
    """
    # Check if the config file exists at the specified path
    if not os.path.exists(config_path):
        print(f"[Config WARNING] Configuration file not found at '{config_path}'. Using default configuration.")
        return DEFAULT_CONFIG

    try:
        # Open the configuration file safely using a context manager
        with open(config_path, 'r') as file_handle:
            # Parse YAML content safely to prevent arbitrary code execution
            config_data = yaml.safe_load(file_handle)
            # If the file is empty, safe_load returns None, so we handle it
            if config_data is None:
                print(f"[Config WARNING] Configuration file '{config_path}' is empty. Using default configuration.")
                return DEFAULT_CONFIG
            
            # Merge with default config to ensure missing keys don't cause crashes later
            merged_config = DEFAULT_CONFIG.copy()
            for key, val in config_data.items():
                if isinstance(val, dict) and key in merged_config:
                    merged_config[key].update(val)
                else:
                    merged_config[key] = val
                    
            return merged_config

    except (yaml.YAMLError, OSError) as error:
        # Handle syntax issues in YAML or file read permission errors
        print(f"[Config ERROR] Failed to parse config file '{config_path}' due to: {error}. Using default configuration.")
        return DEFAULT_CONFIG

if __name__ == "__main__":
    # Test execution block to verify the config module runs correctly by itself
    print("Testing Configuration Loader Module...")
    loaded = load_config()
    print("Agent Node Name:", loaded["agent"]["node_name"])
    print("Process Scan Interval:", loaded["monitors"]["process"]["scan_interval"])
    print("Config Loader Test Passed!")
