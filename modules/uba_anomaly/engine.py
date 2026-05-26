"""
S5: UBA Anomaly Detection Engine.
Ingests logs, builds baselines, and detects anomalous activity.
"""

from __future__ import annotations

import csv
import json
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelcommand.core.events import Event, get_event_bus
from sentinelcommand.core.models import UBABaseline, Alert, AlertSeverity
from sentinelcommand.modules.uba_anomaly.baseline import BaselineModel

logger = logging.getLogger(__name__)


class UBAAnomalyEngine:
    """User Behavior Analytics Anomaly Engine."""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.baseline_model = BaselineModel(alpha=0.1)

    async def get_or_create_baseline(self, user_id: str) -> UBABaseline:
        """Get existing baseline or create a new one."""
        result = await self.db.execute(select(UBABaseline).where(UBABaseline.user_identifier == user_id))
        baseline = result.scalar_one_or_none()
        
        if not baseline:
            baseline = UBABaseline(user_identifier=user_id)
            self.db.add(baseline)
            await self.db.flush()
            
        return baseline

    async def ingest_logs(self, file_path: str) -> dict[str, Any]:
        """Ingest a CSV/JSON log file to build baselines."""
        users_processed = set()
        events_processed = 0
        
        if file_path.endswith(".csv"):
            with open(file_path, "r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    await self._process_training_event(row)
                    users_processed.add(row.get("user_id", "unknown"))
                    events_processed += 1
        elif file_path.endswith(".json"):
            with open(file_path, "r") as f:
                data = json.load(f)
                for row in data:
                    await self._process_training_event(row)
                    users_processed.add(row.get("user_id", "unknown"))
                    events_processed += 1
                    
        await self.db.commit()
        return {"users": len(users_processed), "events": events_processed}

    async def _process_training_event(self, event: dict[str, Any]):
        """Update baselines with historical training data."""
        user_id = event.get("user_id")
        if not user_id:
            return
            
        baseline = await self.get_or_create_baseline(user_id)
        
        # Example: Extract hour from timestamp "2024-01-01T09:15:00Z"
        ts = event.get("timestamp")
        if ts:
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                login_hour = dt.hour + (dt.minute / 60.0)
            except ValueError:
                login_hour = None
        else:
            login_hour = None
            
        file_count = float(event.get("file_count", 0))
        
        self.baseline_model.apply_to_model(baseline, login_hour, file_count)

    async def analyze_event(self, event: dict[str, Any]) -> list[Alert]:
        """Analyze a real-time event against baselines and generate alerts."""
        user_id = event.get("user_id")
        if not user_id:
            return []
            
        baseline = await self.get_or_create_baseline(user_id)
        
        # Don't alert if we don't have enough baseline data
        if baseline.event_count < 10:
            # Still update the baseline
            await self._process_training_event(event)
            await self.db.commit()
            return []
            
        alerts = []
        
        # 1. Login Time Anomaly
        ts = event.get("timestamp")
        if ts:
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                login_hour = dt.hour + (dt.minute / 60.0)
                
                # Check if > 3 standard deviations from mean
                z_score = abs(login_hour - baseline.avg_login_hour) / (baseline.std_login_hour or 1.0)
                if z_score > 3.0:
                    alerts.append(self._create_alert(
                        user_id, "Login Time Anomaly", 
                        f"Login at unusual hour: {login_hour:.1f}. Normal avg: {baseline.avg_login_hour:.1f} (z={z_score:.1f})",
                        min(100.0, z_score * 20), AlertSeverity.MEDIUM
                    ))
            except ValueError:
                pass
                
        # 2. Bulk File Access (Ransomware/Exfil indicator)
        file_count = float(event.get("file_count", 0))
        if file_count > 0:
            z_score = (file_count - baseline.avg_file_access_count) / (baseline.std_file_access_count or 1.0)
            if z_score > 4.0 and file_count > 100:  # Must also be practically large
                alerts.append(self._create_alert(
                    user_id, "Bulk File Access", 
                    f"Accessed {file_count} files in short period. Normal avg: {baseline.avg_file_access_count:.1f} (z={z_score:.1f})",
                    min(100.0, z_score * 15), AlertSeverity.HIGH
                ))
                
        # 3. Geographic Impossibility (Impossible Travel)
        geo = event.get("location")
        if geo and baseline.common_locations:
            try:
                common_locs = json.loads(baseline.common_locations)
                if geo not in common_locs and len(common_locs) >= 2:
                    alerts.append(self._create_alert(
                        user_id, "Impossible Travel", 
                        f"Login from new/impossible location: {geo}",
                        85.0, AlertSeverity.HIGH
                    ))
            except json.JSONDecodeError:
                pass

        # Persist alerts and emit events
        if alerts:
            for alert in alerts:
                self.db.add(alert)
                await get_event_bus().emit(Event(
                    type="uba.alert_generated",
                    source="uba",
                    data={"alert_title": alert.title, "user": user_id, "risk": alert.risk_score}
                ))
                
        # Update baseline with this event
        await self._process_training_event(event)
        await self.db.commit()
        
        return alerts

    def _create_alert(self, user_id: str, title: str, desc: str, score: float, sev: AlertSeverity) -> Alert:
        """Helper to create an Alert model instance."""
        return Alert(
            source_module="uba_anomaly",
            title=title,
            description=desc,
            risk_score=score,
            severity=sev,
            target_user=user_id,
        )
