"""
S7: Ransomware Simulation Engine.
Manages the state, timeline, and real-time execution of a scenario.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from sentinelcommand.core.events import Event, get_event_bus
from sentinelcommand.modules.simulation.scenarios import SCENARIOS, Scenario
from sentinelcommand.modules.simulation.scoring import ScoringEngine

logger = logging.getLogger(__name__)


class SimulationEngine:
    """Manages an active simulation session."""
    
    _instance: SimulationEngine | None = None
    
    def __init__(self):
        self.is_running = False
        self.scenario: Scenario | None = None
        self.current_minute = 0
        self.start_time: datetime | None = None
        self.timeline_log: list[dict] = []
        self.scoring: ScoringEngine | None = None
        self._task: asyncio.Task | None = None
        
        # In a real app, time scale would be 1 minute simulation = 1 minute real time.
        # For testing, we speed it up (1 minute simulation = 2 seconds real time).
        self.time_scale_seconds = 2.0

    @classmethod
    def get_instance(cls) -> SimulationEngine:
        """Singleton pattern for active simulation."""
        if cls._instance is None:
            cls._instance = SimulationEngine()
        return cls._instance

    async def start(self, scenario_id: str) -> dict:
        """Start a new simulation scenario."""
        if self.is_running:
            raise ValueError("A simulation is already running")
            
        if scenario_id not in SCENARIOS:
            raise ValueError(f"Scenario not found: {scenario_id}")
            
        self.scenario = SCENARIOS[scenario_id]
        self.is_running = True
        self.current_minute = 0
        self.start_time = datetime.now(timezone.utc)
        self.timeline_log = []
        self.scoring = ScoringEngine(self.scenario.duration_minutes)
        
        self._log_timeline("system", f"Simulation started: {self.scenario.name}")
        
        # Start background task loop
        self._task = asyncio.create_task(self._simulation_loop())
        
        await get_event_bus().emit(Event(
            type="simulation.started",
            source="simulation",
            data={"scenario_id": scenario_id, "name": self.scenario.name}
        ))
        
        return {"status": "started", "scenario": self.scenario.name}

    async def stop(self) -> dict:
        """Stop the active simulation."""
        if not self.is_running:
            return {"status": "not_running"}
            
        self.is_running = False
        if self._task:
            self._task.cancel()
            
        self._log_timeline("system", "Simulation stopped by user")
        
        final_score = self.scoring.get_final_score() if self.scoring else {}
        
        await get_event_bus().emit(Event(
            type="simulation.stopped",
            source="simulation",
            data={"final_score": final_score}
        ))
        
        return {"status": "stopped", "score": final_score}

    async def _simulation_loop(self):
        """Background loop advancing time and triggering events."""
        try:
            while self.is_running and self.scenario and self.current_minute <= self.scenario.duration_minutes:
                # Find events for this minute
                for event in self.scenario.events:
                    if event.minute == self.current_minute:
                        self._trigger_event(event)
                        
                # Wait for next "minute"
                await asyncio.sleep(self.time_scale_seconds)
                self.current_minute += 1
                
            if self.is_running:
                # Reached the end naturally
                self._log_timeline("system", "Simulation time expired.")
                await self.stop()
                
        except asyncio.CancelledError:
            logger.info("Simulation loop cancelled.")
        except Exception as e:
            logger.error(f"Error in simulation loop: {e}", exc_info=True)
            self.is_running = False

    def _trigger_event(self, event):
        """Trigger a scenario event."""
        self._log_timeline("event", f"[{event.severity}] {event.title} - {event.description}")
        
        # Emit to event bus so the dashboard can pick it up via WebSocket
        asyncio.create_task(get_event_bus().emit(Event(
            type="simulation.scenario_event",
            source="simulation",
            data={
                "minute": self.current_minute,
                "type": event.type,
                "title": event.title,
                "description": event.description,
                "severity": event.severity,
                "details": event.data
            }
        )))

    def _log_timeline(self, type_: str, message: str):
        """Add to internal timeline log."""
        entry = {
            "minute": self.current_minute,
            "real_time": datetime.now(timezone.utc).isoformat(),
            "type": type_,
            "message": message
        }
        self.timeline_log.append(entry)

    async def evaluate_response(self, action_type: str) -> dict:
        """Evaluate a user's response action during the simulation."""
        if not self.is_running or not self.scoring:
            return {"status": "ignored", "message": "Simulation not running"}
            
        result = self.scoring.evaluate_action(action_type, self.current_minute)
        
        if result["points"] > 0:
            self._log_timeline("response", f"Action taken: {action_type} (+{result['points']} pts)")
            
            await get_event_bus().emit(Event(
                type="simulation.score_update",
                source="simulation",
                data={"action": action_type, "points": result["points"], "total_score": self.scoring.score}
            ))
            
        return result

    def get_state(self) -> dict:
        """Get current simulation state."""
        if not self.is_running:
            return {"is_running": False}
            
        return {
            "is_running": True,
            "scenario": self.scenario.name if self.scenario else "",
            "current_minute": self.current_minute,
            "duration": self.scenario.duration_minutes if self.scenario else 60,
            "score": self.scoring.score if self.scoring else 0,
            "timeline": self.timeline_log[-10:]  # Last 10 events
        }
