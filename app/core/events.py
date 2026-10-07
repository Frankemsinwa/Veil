"""Real-time privacy event bus and telemetry broadcasting for desktop cockpit UI."""
import time
import asyncio
from typing import Dict, List, Any, Set
from collections import deque


class PrivacyEventBus:
    """Thread-safe asynchronous pub/sub event broadcaster with a ring buffer for recent history."""

    def __init__(self, history_size: int = 50):
        self.history_size = history_size
        self._subscribers: Set[asyncio.Queue] = set()
        self._history: deque = deque(maxlen=history_size)
        self._lock = None


    def _get_lock(self):
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def subscribe(self) -> asyncio.Queue:
        """Register a new WebSocket subscriber queue."""
        queue: asyncio.Queue = asyncio.Queue(maxsize=100)
        async with self._get_lock():
            self._subscribers.add(queue)
        return queue

    async def unsubscribe(self, queue: asyncio.Queue):
        """Unregister a disconnected subscriber queue."""
        async with self._get_lock():
            self._subscribers.discard(queue)

    def publish_sync(self, event_type: str, data: Dict[str, Any]):
        """Synchronously publish an event from synchronous pipeline code."""
        event = {
            "type": event_type,
            "timestamp": time.time(),
            "data": data
        }
        self._history.append(event)

        # Non-blocking dispatch to active subscriber queues
        for q in list(self._subscribers):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                try:
                    q.get_nowait()
                    q.put_nowait(event)
                except Exception:
                    pass
            except Exception:
                pass


    async def publish(self, event_type: str, data: Dict[str, Any]):
        """Asynchronously broadcast an event to all connected subscriber queues."""
        event = {
            "type": event_type,
            "timestamp": time.time(),
            "data": data
        }
        self._history.append(event)

        async with self._get_lock():
            for q in list(self._subscribers):
                try:
                    q.put_nowait(event)
                except asyncio.QueueFull:
                    try:
                        q.get_nowait()
                        q.put_nowait(event)
                    except Exception:
                        pass

    def get_recent_history(self) -> List[Dict[str, Any]]:
        """Returns the most recent privacy events for newly connected UI clients."""
        return list(self._history)

    def clear(self):
        """Resets history and active subscribers."""
        self._history.clear()
        self._subscribers.clear()


# Global event bus singleton
privacy_event_bus = PrivacyEventBus()
