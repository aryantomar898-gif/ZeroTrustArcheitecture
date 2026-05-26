"""
In-process async event bus for module-to-module communication.
Supports publish/subscribe pattern with optional Redis adapter.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine

logger = logging.getLogger(__name__)


@dataclass
class Event:
    """Represents a platform event."""
    type: str
    source: str
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: str = ""

    def __post_init__(self):
        if not self.id:
            import uuid
            self.id = str(uuid.uuid4())


# Type alias for event handlers
EventHandler = Callable[[Event], Coroutine[Any, Any, None]]


class EventBus:
    """
    Async event bus with pub/sub pattern.

    Usage:
        bus = EventBus()

        @bus.on("killswitch.activated")
        async def handle_killswitch(event: Event):
            print(f"Kill switch activated: {event.data}")

        await bus.emit(Event(type="killswitch.activated", source="killswitch", data={"level": 3}))
    """

    def __init__(self):
        self._handlers: dict[str, list[EventHandler]] = defaultdict(list)
        self._wildcard_handlers: list[EventHandler] = []
        self._history: list[Event] = []
        self._max_history: int = 1000

    def on(self, event_type: str) -> Callable:
        """Decorator to register an event handler."""
        def decorator(handler: EventHandler) -> EventHandler:
            self._handlers[event_type].append(handler)
            return handler
        return decorator

    def subscribe(self, event_type: str, handler: EventHandler) -> None:
        """Programmatically subscribe a handler to an event type."""
        self._handlers[event_type].append(handler)

    def subscribe_all(self, handler: EventHandler) -> None:
        """Subscribe a handler to ALL events (wildcard)."""
        self._wildcard_handlers.append(handler)

    def unsubscribe(self, event_type: str, handler: EventHandler) -> None:
        """Remove a handler from an event type."""
        if handler in self._handlers[event_type]:
            self._handlers[event_type].remove(handler)

    async def emit(self, event: Event) -> None:
        """
        Emit an event to all registered handlers.
        Handlers are executed concurrently via asyncio.gather.
        """
        self._history.append(event)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]

        handlers = list(self._handlers.get(event.type, []))
        handlers.extend(self._wildcard_handlers)

        if not handlers:
            logger.debug(f"No handlers for event: {event.type}")
            return

        tasks = []
        for handler in handlers:
            tasks.append(self._safe_call(handler, event))

        await asyncio.gather(*tasks)

    async def _safe_call(self, handler: EventHandler, event: Event) -> None:
        """Call a handler with error catching."""
        try:
            await handler(event)
        except Exception as e:
            logger.error(
                f"Error in event handler {handler.__name__} for {event.type}: {e}",
                exc_info=True,
            )

    def get_history(self, event_type: str | None = None, limit: int = 100) -> list[Event]:
        """Get recent event history, optionally filtered by type."""
        events = self._history
        if event_type:
            events = [e for e in events if e.type == event_type]
        return events[-limit:]


# ── Global singleton ─────────────────────────────────────────────────

_event_bus: EventBus | None = None


def get_event_bus() -> EventBus:
    """Get or create the global event bus singleton."""
    global _event_bus
    if _event_bus is None:
        _event_bus = EventBus()
    return _event_bus
