"""
S7: Pydantic schemas for Simulation API.
"""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel


class StartSimulationRequest(BaseModel):
    scenario_id: str


class ResponseActionRequest(BaseModel):
    action_type: str


class SimulationStateResponse(BaseModel):
    is_running: bool
    scenario: str | None = None
    current_minute: int | None = None
    duration: int | None = None
    score: int | None = None
    timeline: list[dict[str, Any]] = []
