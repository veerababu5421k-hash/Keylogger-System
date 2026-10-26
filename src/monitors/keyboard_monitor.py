import os
import time
import threading
import evdev
import psutil
from src.monitors.base_monitor import BaseMonitor

class KeyboardMonitor(BaseMonitor):
    """
    Monitors Linux input subsystems (/dev/input/event*) to measure typing rate anomalies,
    detect active keyboard devices, and scan for unauthorized processes reading key streams.
    """
    def __init__(self, config, threat_engine):
        super().__init__("KeyboardMonitor", config)
        self.threat_engine = threat_engine
        
        kb_config = self.config.get("monitors", {}).get("keyboard", {})
        self.device_path = kb_config.get("device_path", "/dev/input")
        self.rate_threshold = kb_config.get("keystroke_rate_threshold", 20.0)
        
        self.keystroke_counter = 0
        self.counter_lock = threading.Lock()
        self.last_check_time = time.time()
        self.device_threads = []
        self.whitelisted_readers = {"Xorg", "gnome-shell", "systemd-logind", "udevd", "wayland", "gdm", "lightdm", "kwin"}
        self.my_pid = os.getpid()

    def start(self):
        """
        Starts keyboard listeners and the base thread.
        """
        self.logger.info("Initializing keyboard monitor...")
        self._start_device_listeners()
        super().start()

    def stop(self):
        """
        Stops base thread and clean up sub-listeners.
        """
        super().stop()
        # Note: evdev read loops are blocking; they will clean up when the main process exits

    def _start_device_listeners(self):
        """
        Finds all active keyboard devices and registers background listeners.
        """
        try:
            device_paths = evdev.list_devices()
            keyboards_found = 0
            
            for path in device_paths:
                try:
                    dev = evdev.InputDevice(path)
                    capabilities = dev.capabilities()
                    
                    # Verify if it has EV_KEY capabilities (keyboards report EV_KEY support)
                    # and matches keyboard-like device name
                    is_keyboard = "keyboard" in dev.name.lower() or evdev.ecodes.EV_KEY in capabilities
                    
                    if is_keyboard:
                        keyboards_found += 1
                        t = threading.Thread(target=self._device_listener_loop, args=(path,), name=f"EvdevListener-{os.path.basename(path)}", daemon=True)
                        t.start()
                        self.device_threads.append(t)
                        self.logger.info("Listening to keyboard device: %s (%s)", dev.name, path)
                except Exception as e:
                    self.logger.debug("Skipped input device %s: %s", path, e)
            
            self.logger.info("Started %d evdev input listener threads.", keyboards_found)
        except Exception as e:
            self.logger.error("Failed to list input devices: %s", e)

    def _device_listener_loop(self, dev_path):
        """
        Blocking event reader thread.
        """
        try:
            dev = evdev.InputDevice(dev_path)
            for event in dev.read_loop():
                if not self.running:
                    break
                # EV_KEY represents key events. event.value == 1 is key down (press)
                if event.type == evdev.ecodes.EV_KEY and event.value == 1:
                    with self.counter_lock:
                        self.keystroke_counter += 1
        except Exception as e:
            self.logger.debug("Input event reader terminated on %s: %s", dev_path, e)

    def scan(self):
        """
        Tick check:
        1. Calculates key rate over interval and flags high speeds.
        2. Scans running processes to detect unauthorized readers of /dev/input/event*.
        """
        now = time.time()
        elapsed = now - self.last_check_time
        if elapsed <= 0:
            elapsed = 1.0

        # 1. Audit keystroke rates
        with self.counter_lock:
            rate = self.keystroke_counter / elapsed
            self.keystroke_counter = 0
        self.last_check_time = now

        self.logger.debug("Current keystroke rate: %.2f keys/sec", rate)

        if rate > self.rate_threshold:
            self.threat_engine.report_event(
                monitor="keyboard",
                message=f"Abnormal keyboard activity detected: rate of {rate:.1f} keystrokes/sec exceeds limit of {self.rate_threshold}",
                risk_score=65.0,
                extra_info={"typing_rate": rate}
            )

        # 2. Audit unauthorized file handles on input event character nodes
        self._audit_unauthorized_input_readers()

    def _audit_unauthorized_input_readers(self):
        """
        Scans running process handles to see if unwhitelisted processes are reading /dev/input/event*
        """
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']

                # Skip whitelisted readers and our own agent
                if pid == self.my_pid or name in self.whitelisted_readers:
                    continue

                # Scan open file descriptors
                for file_handle in proc.open_files():
                    if "/dev/input/event" in file_handle.path:
                        self.threat_engine.report_event(
                            monitor="keyboard",
                            message=f"Unauthorized Input Reader: Process '{name}' (PID {pid}) is holding a read lock on keyboard device handle '{file_handle.path}'",
                            risk_score=95.0,
                            pid=pid,
                            extra_info={"open_file_handle": file_handle.path}
                        )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                self.logger.debug("Error auditing process open files: %s", e)
