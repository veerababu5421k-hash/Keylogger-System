"""
Thread-safe Event Bus for Multi-Agent Communication.
All agents publish monitoring events exclusively to the EventBus.
Only the Orchestrator consumes events from the EventBus.
"""

import queue
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("OrchestratorEventBus")

class EventBus:
    """
    Thread-safe event queue ensuring strictly isolated multi-agent communication.
    Agents publish events to this queue; the Orchestrator consumes them.
    """
    def __init__(self, maxsize: int = 1000):
        self._queue: queue.Queue = queue.Queue(maxsize=maxsize)

    def publish(self, event: Dict[str, Any]) -> bool:
        """
        Publish a telemetry/monitoring event to the EventBus.
        """
        try:
            self._queue.put_nowait(event)
            return True
        except queue.Full:
            logger.warning("EventBus queue full! Event dropped: %s", event.get("event_type", "unknown"))
            return False

    def get_event(self, timeout: float = 0.5) -> Optional[Dict[str, Any]]:
        """
        Retrieve the next event from the queue (called exclusively by Orchestrator).
        """
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def empty(self) -> bool:
        return self._queue.empty()

    def qsize(self) -> int:
        return self._queue.qsize()
