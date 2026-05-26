"""
S8: Rule Engine for Production UBA.
Supports built-in rules and a custom YAML-based Rule DSL.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

from sentinelcommand.core.models import UBABaseline, AlertSeverity

logger = logging.getLogger(__name__)


class UBARule(ABC):
    """Abstract base for UBA rules."""
    
    name: str
    description: str
    severity: AlertSeverity
    
    @abstractmethod
    def evaluate(self, event: dict[str, Any], baseline: UBABaseline) -> tuple[bool, float, str]:
        """
        Evaluate an event against a baseline.
        Returns: (is_anomaly, risk_score, reason_string)
        """
        ...


class LoginTimeRule(UBARule):
    name = "Login Time Anomaly"
    description = "Detects logins outside normal working hours for this user."
    severity = AlertSeverity.MEDIUM
    
    def evaluate(self, event: dict[str, Any], baseline: UBABaseline) -> tuple[bool, float, str]:
        if "login_hour" not in event:
            return False, 0.0, ""
            
        hour = float(event["login_hour"])
        z_score = abs(hour - baseline.avg_login_hour) / (baseline.std_login_hour or 1.0)
        
        if z_score > 3.0:
            risk = min(100.0, z_score * 20.0)
            return True, risk, f"Login at unusual hour: {hour:.1f}. Normal avg: {baseline.avg_login_hour:.1f} (z={z_score:.1f})"
            
        return False, 0.0, ""


class BulkFileAccessRule(UBARule):
    name = "Bulk File Access"
    description = "Detects unusually high volume of file access (potential ransomware/exfil)."
    severity = AlertSeverity.HIGH
    
    def evaluate(self, event: dict[str, Any], baseline: UBABaseline) -> tuple[bool, float, str]:
        if "file_count" not in event:
            return False, 0.0, ""
            
        count = float(event["file_count"])
        z_score = (count - baseline.avg_file_access_count) / (baseline.std_file_access_count or 1.0)
        
        if z_score > 4.0 and count > 100:
            risk = min(100.0, z_score * 15.0)
            return True, risk, f"Accessed {count} files. Normal avg: {baseline.avg_file_access_count:.1f} (z={z_score:.1f})"
            
        return False, 0.0, ""


class ImpossibleTravelRule(UBARule):
    name = "Impossible Travel"
    description = "Detects logins from locations not typically seen for this user."
    severity = AlertSeverity.HIGH
    
    def evaluate(self, event: dict[str, Any], baseline: UBABaseline) -> tuple[bool, float, str]:
        geo = event.get("location")
        if not geo or not baseline.common_locations:
            return False, 0.0, ""
            
        import json
        try:
            common_locs = json.loads(baseline.common_locations)
            if geo not in common_locs and len(common_locs) >= 2:
                return True, 85.0, f"Login from new/impossible location: {geo}"
        except json.JSONDecodeError:
            pass
            
        return False, 0.0, ""


# In a real app, this would dynamically compile python expressions from YAML
class CustomDSLRule(UBARule):
    def __init__(self, name: str, severity: AlertSeverity, condition: str, risk_expr: str):
        self.name = name
        self.description = f"Custom rule: {condition}"
        self.severity = severity
        self._condition = condition
        self._risk_expr = risk_expr
        
    def evaluate(self, event: dict[str, Any], baseline: UBABaseline) -> tuple[bool, float, str]:
        # DANGEROUS IN PRODUCTION: Use a secure eval (like ast.literal_eval or a real DSL parser)
        # We use standard eval here purely for demonstration of the concept
        try:
            # Setup context
            ctx = {"event": event, "baseline": baseline}
            
            # Evaluate condition (e.g. "event.get('action') == 'delete' and event.get('file_count', 0) > 50")
            is_anomaly = eval(self._condition, {}, ctx)
            
            if is_anomaly:
                # Evaluate risk (e.g. "min(100, event.get('file_count', 0) * 2)")
                risk = float(eval(self._risk_expr, {}, ctx))
                return True, risk, f"Triggered custom rule '{self.name}'"
                
        except Exception as e:
            logger.error(f"Error evaluating custom rule {self.name}: {e}")
            
        return False, 0.0, ""


BUILTIN_RULES = [
    LoginTimeRule(),
    BulkFileAccessRule(),
    ImpossibleTravelRule(),
]
