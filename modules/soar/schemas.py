"""
S9: Pydantic schemas for SOAR API.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from pydantic import BaseModel


class ExecutePlaybookRequest(BaseModel):
    context: dict[str, Any] = {}


class PlaybookSchema(BaseModel):
    id: str
    name: str
    description: str


class ExecutionResponse(BaseModel):
    id: int
    playbook_name: str
    status: str
    started_at: datetime
    completed_at: datetime | None
    current_step: int
    total_steps: int
    execution_log: list[dict]
