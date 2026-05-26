"""
S7: Pre-built scenarios for the simulation platform.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScenarioEvent:
    """An event that occurs during the simulation at a specific minute mark."""
    minute: int
    type: str  # e.g., 'alert', 'file_encryption', 'login'
    title: str
    description: str
    severity: str
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class Scenario:
    """A simulation scenario definition."""
    id: str
    name: str
    description: str
    duration_minutes: int
    events: list[ScenarioEvent]


# The primary CountryEdu ransomware scenario from the document
COUNTRYEDU_RANSOMWARE = Scenario(
    id="scenario_countryedu_01",
    name="CountryEdu Ransomware Containment",
    description="Simulates the CountryEdu ransomware incident. You have 60 minutes to contain the spread.",
    duration_minutes=60,
    events=[
        ScenarioEvent(
            minute=1,
            type="alert",
            title="UBA Alert: Login Time Anomaly",
            description="User 'Alice IT' logged in at 2:00 AM (3 std devs from baseline).",
            severity="MEDIUM",
            data={"user_id": "alice_it"}
        ),
        ScenarioEvent(
            minute=5,
            type="alert",
            title="UBA Alert: Bulk File Access",
            description="User 'Alice IT' accessed 15,000 files on Finance Share.",
            severity="HIGH",
            data={"user_id": "alice_it", "share": "Finance"}
        ),
        ScenarioEvent(
            minute=10,
            type="file_encryption",
            title="Ransomware: Encryption Started",
            description="High CPU usage and mass file modifications detected on File Server 1.",
            severity="CRITICAL",
            data={"host": "fs-01.countryedu.local"}
        ),
        ScenarioEvent(
            minute=15,
            type="lateral_movement",
            title="Network Anomaly: SMB Scanning",
            description="Host fs-01 is aggressively scanning ports 445 and 139 across the 10.0.x.x subnet.",
            severity="CRITICAL",
            data={"src": "fs-01", "ports": [445, 139]}
        ),
        ScenarioEvent(
            minute=30,
            type="file_encryption",
            title="Ransomware: Spread to Domain Controller",
            description="Encryption detected on DC-01. Directory services degraded.",
            severity="CRITICAL",
            data={"host": "dc-01.countryedu.local"}
        ),
        ScenarioEvent(
            minute=50,
            type="data_exfiltration",
            title="Network Anomaly: Outbound Traffic Spike",
            description="250GB of data transferred to unknown external IP via HTTPS.",
            severity="CRITICAL",
            data={"dst_ip": "198.51.100.42"}
        ),
    ]
)

SCENARIOS = {
    COUNTRYEDU_RANSOMWARE.id: COUNTRYEDU_RANSOMWARE,
}
