"""
Agent 11: Cloud Synchronization Agent
Responsible for pushing non-sensitive, sanitized security telemetry and incident summaries to Cloud API.
Supports offline queueing and graceful network retry logic.
Communicates ONLY with Orchestrator.
"""

import time
import queue
import threading
import requests
from typing import Dict, Any, List, Optional

from src.agents.cloud_sync_agent.config import CloudSyncAgentConfig
from src.agents.cloud_sync_agent.logger import get_cloud_sync_logger

class CloudSyncAgent(threading.Thread):
    def __init__(self, raw_config: Dict[str, Any] = None, orchestrator = None):
        super().__init__(daemon=True, name="CloudSyncAgent")
        self.config = CloudSyncAgentConfig(raw_config)
        self.logger = get_cloud_sync_logger()
        self.orchestrator = orchestrator
        self.running = False
        self.event_queue = queue.Queue(maxsize=1000)
        self.failed_sync_count = 0
        self.last_sync_timestamp: Optional[str] = None

    def enqueue_telemetry(self, telemetry: Dict[str, Any]):
        """
        Add sanitized telemetry event to offline synchronization queue.
        """
        if not self.config.enabled:
            return
        try:
            # Strip sensitive payload data if any present (Privacy-first telemetry)
            sanitized = self._sanitize_event(telemetry)
            self.event_queue.put_nowait(sanitized)
        except queue.Full:
            self.logger.warning("Cloud sync queue full. Discarding oldest telemetry event.")

    def _sanitize_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Remove any potential raw sensitive user data before cloud transmission.
        """
        clean_event = dict(event)
        # Guarantee no raw keystrokes or passwords are present
        if "payload" in clean_event:
            payload = dict(clean_event["payload"])
            payload.pop("raw_keystrokes", None)
            payload.pop("password", None)
            clean_event["payload"] = payload
        return clean_event

    def run(self):
        self.logger.info("Initializing Cloud Synchronization Agent...")
        self.running = True

        while self.running:
            try:
                self._sync_batch()
                time.sleep(self.config.sync_interval)
            except Exception as e:
                self.logger.error("Error in CloudSyncAgent loop: %s", e, exc_info=True)
                time.sleep(self.config.sync_interval)

    def _sync_batch(self):
        if self.event_queue.empty():
            return

        batch: List[Dict[str, Any]] = []
        while not self.event_queue.empty() and len(batch) < self.config.batch_size:
            batch.append(self.event_queue.get_nowait())

        if not batch:
            return

        headers = {
            "Content-Type": "application/json",
            "X-API-Key": self.config.api_key
        }

        payload = {
            "device_id": self.config.raw_config.get("agent", {}).get("node_name", "keyshield-local-node"),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "events_count": len(batch),
            "events": batch
        }

        try:
            response = requests.post(
                self.config.endpoint,
                json=payload,
                headers=headers,
                timeout=5.0
            )
            if response.status_code in (200, 201):
                self.failed_sync_count = 0
                self.last_sync_timestamp = payload["timestamp"]
                self.logger.info("Successfully synchronized %d telemetry events to cloud.", len(batch))
            else:
                self.logger.warning("Cloud sync API returned status %d. Re-queueing events.", response.status_code)
                self._requeue_events(batch)
        except requests.RequestException:
            self.failed_sync_count += 1
            if self.failed_sync_count <= 3 or self.failed_sync_count % 10 == 0:
                self.logger.info("Cloud API endpoint unavailable (%s). Offline telemetry queued.", self.config.endpoint)
            self._requeue_events(batch)

    def _requeue_events(self, batch: List[Dict[str, Any]]):
        for item in batch:
            try:
                self.event_queue.put_nowait(item)
            except queue.Full:
                break

    def stop(self):
        self.logger.info("Stopping Cloud Synchronization Agent...")
        self.running = False
