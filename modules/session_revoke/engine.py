"""
S1: Session Revocation Engine
Connects to Microsoft Entra ID (Azure AD) and revokes user sessions.
Supports both real (Azure Graph API) and simulated modes.
"""

from __future__ import annotations

import json
import logging
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from sentinelcommand.core.config import get_settings
from sentinelcommand.core.events import Event, get_event_bus

logger = logging.getLogger(__name__)
_settings = get_settings()


@dataclass
class EntraUser:
    """Represents a user from Microsoft Entra ID."""
    id: str
    display_name: str
    email: str
    department: str = ""
    job_title: str = ""
    account_enabled: bool = True


@dataclass
class RevocationResult:
    """Result of a session revocation attempt."""
    user_id: str
    user_email: str
    department: str
    success: bool
    error: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class BaseSessionEngine(ABC):
    """Abstract base for session revocation engines."""

    @abstractmethod
    async def authenticate(self) -> bool:
        """Authenticate to the identity provider."""
        ...

    @abstractmethod
    async def list_users(self, department: str | None = None) -> list[EntraUser]:
        """List all users, optionally filtered by department."""
        ...

    @abstractmethod
    async def revoke_user_sessions(self, user_id: str) -> RevocationResult:
        """Revoke all sessions for a specific user."""
        ...

    async def revoke_all_sessions(
        self,
        department: str | None = None,
        progress_callback=None,
    ) -> list[RevocationResult]:
        """Revoke sessions for all users (optionally in a department)."""
        users = await self.list_users(department)
        results = []

        for i, user in enumerate(users):
            result = await self.revoke_user_sessions(user.id)
            results.append(result)

            if progress_callback:
                progress_callback(i + 1, len(users), user.display_name)

        # Emit event
        bus = get_event_bus()
        await bus.emit(Event(
            type="session.bulk_revocation",
            source="session_revoke",
            data={
                "total": len(results),
                "success": sum(1 for r in results if r.success),
                "failed": sum(1 for r in results if not r.success),
                "department": department,
            },
        ))

        return results


class SimulatedSessionEngine(BaseSessionEngine):
    """
    Simulated session engine for demos and testing.
    Generates fake users and simulates revocation.
    """

    _DEPARTMENTS = ["IT", "Finance", "HR", "Engineering", "Marketing", "Legal", "Executive"]
    _NAMES = [
        "Alice Johnson", "Bob Smith", "Carol Williams", "David Brown", "Eva Martinez",
        "Frank Anderson", "Grace Lee", "Henry Wilson", "Ivy Chen", "Jack Thompson",
        "Karen Davis", "Leo Garcia", "Maria Rodriguez", "Nathan Clark", "Olivia Taylor",
        "Patrick Moore", "Quinn White", "Rachel Harris", "Steve Martin", "Tina Jackson",
    ]

    def __init__(self):
        self._authenticated = False
        self._users: list[EntraUser] = []
        self._generate_users()

    def _generate_users(self):
        """Generate simulated users."""
        import random
        random.seed(42)
        for i, name in enumerate(self._NAMES):
            dept = self._DEPARTMENTS[i % len(self._DEPARTMENTS)]
            email = name.lower().replace(" ", ".") + "@countryedu.org"
            self._users.append(EntraUser(
                id=str(uuid.uuid4()),
                display_name=name,
                email=email,
                department=dept,
                job_title=f"Senior {dept} Specialist",
                account_enabled=True,
            ))

    async def authenticate(self) -> bool:
        self._authenticated = True
        logger.info("[SIMULATED] Authenticated to Entra ID via device code flow")
        return True

    async def list_users(self, department: str | None = None) -> list[EntraUser]:
        if not self._authenticated:
            await self.authenticate()
        users = self._users
        if department:
            users = [u for u in users if u.department.lower() == department.lower()]
        return users

    async def revoke_user_sessions(self, user_id: str) -> RevocationResult:
        user = next((u for u in self._users if u.id == user_id), None)
        if user is None:
            return RevocationResult(
                user_id=user_id, user_email="unknown", department="",
                success=False, error="User not found",
            )

        logger.info(f"[SIMULATED] Revoked sessions for {user.display_name} ({user.email})")
        return RevocationResult(
            user_id=user_id, user_email=user.email,
            department=user.department, success=True,
        )


class AzureSessionEngine(BaseSessionEngine):
    """
    Real Microsoft Entra ID session engine.
    Uses Microsoft Graph API to revoke sessions.
    Requires AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET in config.
    """

    GRAPH_BASE = "https://graph.microsoft.com/v1.0"

    def __init__(self):
        self._access_token: str | None = None
        self._client = httpx.AsyncClient(timeout=30.0)

    async def authenticate(self) -> bool:
        """Authenticate using client credentials flow."""
        if not _settings.AZURE_TENANT_ID or not _settings.AZURE_CLIENT_ID:
            raise RuntimeError(
                "Azure AD credentials not configured. "
                "Set AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET in .env"
            )

        token_url = (
            f"https://login.microsoftonline.com/{_settings.AZURE_TENANT_ID}/oauth2/v2.0/token"
        )
        data = {
            "grant_type": "client_credentials",
            "client_id": _settings.AZURE_CLIENT_ID,
            "client_secret": _settings.AZURE_CLIENT_SECRET,
            "scope": "https://graph.microsoft.com/.default",
        }

        resp = await self._client.post(token_url, data=data)
        resp.raise_for_status()
        self._access_token = resp.json()["access_token"]
        logger.info("Authenticated to Microsoft Entra ID")
        return True

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._access_token}"}

    async def list_users(self, department: str | None = None) -> list[EntraUser]:
        if not self._access_token:
            await self.authenticate()

        url = f"{self.GRAPH_BASE}/users?$select=id,displayName,mail,department,jobTitle,accountEnabled"
        if department:
            url += f"&$filter=department eq '{department}'"

        users = []
        while url:
            resp = await self._client.get(url, headers=self._headers())
            resp.raise_for_status()
            data = resp.json()
            for u in data.get("value", []):
                users.append(EntraUser(
                    id=u["id"],
                    display_name=u.get("displayName", ""),
                    email=u.get("mail", ""),
                    department=u.get("department", ""),
                    job_title=u.get("jobTitle", ""),
                    account_enabled=u.get("accountEnabled", True),
                ))
            url = data.get("@odata.nextLink")

        return users

    async def revoke_user_sessions(self, user_id: str) -> RevocationResult:
        if not self._access_token:
            await self.authenticate()

        url = f"{self.GRAPH_BASE}/users/{user_id}/revokeSignInSessions"
        try:
            resp = await self._client.post(url, headers=self._headers())
            resp.raise_for_status()
            user = next(
                (u for u in await self.list_users() if u.id == user_id),
                None,
            )
            return RevocationResult(
                user_id=user_id,
                user_email=user.email if user else "",
                department=user.department if user else "",
                success=True,
            )
        except Exception as e:
            return RevocationResult(
                user_id=user_id, user_email="", department="",
                success=False, error=str(e),
            )


def get_session_engine() -> BaseSessionEngine:
    """Factory: return simulated or real engine based on config."""
    if _settings.SIMULATION_MODE or not _settings.AZURE_TENANT_ID:
        return SimulatedSessionEngine()
    return AzureSessionEngine()


def save_revocation_log(results: list[RevocationResult], output_path: str | None = None) -> str:
    """Save revocation results to a JSON file."""
    if output_path is None:
        output_path = str(
            Path(_settings.DATA_DIR) / f"revocation_log_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
        )

    data = [
        {
            "user_id": r.user_id,
            "user_email": r.user_email,
            "department": r.department,
            "success": r.success,
            "error": r.error,
            "timestamp": r.timestamp.isoformat(),
        }
        for r in results
    ]

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)

    return output_path
