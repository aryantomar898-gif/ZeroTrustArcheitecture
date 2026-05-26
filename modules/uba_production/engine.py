"""
S8: Production UBA Engine.
Scalable, deduplicating, multi-rule ML baseline engine.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelcommand.core.events import Event, get_event_bus
from sentinelcommand.core.models import UBABaseline, Alert, AlertSeverity
from sentinelcommand.modules.uba_anomaly.baseline import BaselineModel
from sentinelcommand.modules.uba_production.rules import BUILTIN_RULES, UBARule

logger = logging.getLogger(__name__)


class ProductionUBAEngine:
    """Production-grade streaming UBA engine."""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.baseline_model = BaselineModel(alpha=0.05)  # Slower adaptation for prod
        self.rules: list[UBARule] = list(BUILTIN_RULES)
        self.dedup_window = timedelta(hours=1)
        
    async def load_custom_rules(self, yaml_path: str):
        """Load custom rules from a YAML DSL file."""
        import yaml
        from sentinelcommand.modules.uba_production.rules import CustomDSLRule
        
        try:
            with open(yaml_path, "r") as f:
                data = yaml.safe_load(f)
                
            for rule_data in data.get("rules", []):
                rule = CustomDSLRule(
                    name=rule_data["name"],
                    severity=AlertSeverity(rule_data.get("severity", "MEDIUM")),
                    condition=rule_data["condition"],
                    risk_expr=rule_data.get("risk", "50.0")
                )
                self.rules.append(rule)
                logger.info(f"Loaded custom rule: {rule.name}")
        except FileNotFoundError:
            logger.warning(f"Custom rules file not found: {yaml_path}")
        except Exception as e:
            logger.error(f"Failed to load custom rules: {e}")

    async def get_baseline(self, user_id: str) -> UBABaseline:
        """Get baseline for user (creates if missing)."""
        result = await self.db.execute(select(UBABaseline).where(UBABaseline.user_identifier == user_id))
        baseline = result.scalar_one_or_none()
        
        if not baseline:
            baseline = UBABaseline(user_identifier=user_id)
            self.db.add(baseline)
            await self.db.flush()
            
        return baseline

    async def _is_deduplicated(self, user_id: str, rule_name: str) -> bool:
        """Check if we recently fired this exact alert for this user."""
        cutoff = datetime.now(timezone.utc) - self.dedup_window
        
        result = await self.db.execute(
            select(Alert).where(
                Alert.target_user == user_id,
                Alert.title == rule_name,
                Alert.timestamp >= cutoff
            ).limit(1)
        )
        return result.scalar_one_or_none() is not None

    async def process_event(self, event: dict[str, Any]) -> list[Alert]:
        """
        Process a single streaming event.
        1. Parse event
        2. Fetch baseline
        3. Evaluate rules
        4. Deduplicate alerts
        5. Update baseline
        """
        user_id = event.get("user_id")
        if not user_id:
            return []
            
        # 1. Parse Event Extras
        ts_str = event.get("timestamp")
        if ts_str:
            try:
                dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                event["login_hour"] = dt.hour + (dt.minute / 60.0)
            except ValueError:
                pass
                
        baseline = await self.get_baseline(user_id)
        alerts = []
        
        # 2. Evaluate Rules (if we have enough baseline data)
        if baseline.event_count >= 10:
            for rule in self.rules:
                is_anomaly, risk, reason = rule.evaluate(event, baseline)
                
                if is_anomaly:
                    # 3. Deduplicate
                    if await self._is_deduplicated(user_id, rule.name):
                        logger.debug(f"Suppressed duplicate alert: {rule.name} for {user_id}")
                        continue
                        
                    alert = Alert(
                        source_module="uba_production",
                        title=rule.name,
                        description=reason,
                        risk_score=risk,
                        severity=rule.severity,
                        target_user=user_id,
                        raw_data=str(event)
                    )
                    self.db.add(alert)
                    alerts.append(alert)
                    
                    # Emit event bus notification
                    await get_event_bus().emit(Event(
                        type="uba.prod_alert",
                        source="uba_production",
                        data={"title": alert.title, "user": user_id, "risk": risk}
                    ))

        # 4. Update Baseline
        self.baseline_model.apply_to_model(
            baseline, 
            login_hour=event.get("login_hour"), 
            file_count=float(event.get("file_count", 0)) if "file_count" in event else None
        )
        
        baseline.last_updated = datetime.now(timezone.utc)
        await self.db.commit()
        
        return alerts
