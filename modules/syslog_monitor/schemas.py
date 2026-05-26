"""
S10: Pydantic schemas for System Log Monitor API.
"""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel


class RemediationAction(BaseModel):
    id: str
    severity: str
    title: str
    description: str
    steps: list[str]


class LogSummary(BaseModel):
    critical: int
    error: int
    warning: int
    information: int


class LogEntry(BaseModel):
    timestamp: str
    event_id: int | None
    severity: str
    provider: str
    message: str


class SystemHealthReport(BaseModel):
    summary: LogSummary
    actions: list[RemediationAction]
    logs: list[LogEntry]
