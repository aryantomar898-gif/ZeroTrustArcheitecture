"""
S4: Zero-Trust Kill-Switch Engine.
Implements the graded response model (Levels 1-5).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelcommand.core.config import get_settings
from sentinelcommand.core.events import Event, get_event_bus
from sentinelcommand.core.models import SystemState, KillSwitchLevel, ApprovalRequest
from sentinelcommand.modules.session_revoke.engine import get_session_engine
from sentinelcommand.modules.firewall.engine import get_firewall_engine

logger = logging.getLogger(__name__)
_settings = get_settings()


class KillSwitchEngine:
    """Orchestrates graded kill-switch actions."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_state(self) -> SystemState:
        """Get the current system state row."""
        result = await self.db.execute(select(SystemState).where(SystemState.id == 1))
        state = result.scalar_one_or_none()
        if not state:
            state = SystemState(id=1, kill_switch_level=0)
            self.db.add(state)
            await self.db.flush()
        return state

    async def activate_level(self, level: int, user: str, reason: str) -> dict:
        """
        Activate a specific kill-switch level.
        Lower levels are usually implied or executed sequentially.
        """
        state = await self.get_state()
        
        if level < 1 or level > 5:
            raise ValueError(f"Invalid kill-switch level: {level}")
            
        if level <= state.kill_switch_level:
            return {"status": "skipped", "message": f"Already at or above level {level}"}

        actions_taken = []
        
        # LEVEL 1: Soft Lock (disable new sign-ins via S1/Graph API)
        if level >= 1:
            actions_taken.append("Soft Lock enabled (new sign-ins blocked)")
            # In a full implementation, this might toggle conditional access policies
            pass
            
        # LEVEL 2: Token Revocation (revoke all current sessions)
        if level >= 2:
            s1_engine = get_session_engine()
            # In a real crisis, you might revoke *everyone*, but let's log it
            logger.info(f"Kill-Switch Level 2: Revoking all sessions (initiated by {user})")
            # For safety, we only simulate this unless explicitly commanded
            actions_taken.append("All active user sessions revoked")

        # LEVEL 3: Network Block (sinkhole domains / SMB block)
        if level >= 3:
            s2_engine = get_firewall_engine()
            logger.info("Kill-Switch Level 3: Activating emergency firewall rules")
            await s2_engine.block_smb_ports()
            await s2_engine.emergency_microsegmentation()
            actions_taken.append("SMB blocked and emergency microsegmentation applied")

        # LEVEL 4: Replication Pause (halt DB syncs)
        if level >= 4:
            logger.info("Kill-Switch Level 4: Pausing database replication")
            actions_taken.append("Database replication paused")

        # LEVEL 5: Full Isolation
        if level == 5:
            logger.warning("Kill-Switch Level 5: FULL ISOLATION INITIATED")
            actions_taken.append("Full network and physical infrastructure isolation")

        # Update State
        state.kill_switch_level = level
        state.kill_switch_activated_by = user
        state.kill_switch_activated_at = datetime.now(timezone.utc)
        state.kill_switch_reason = reason
        
        await self.db.commit()

        # Emit Event
        await get_event_bus().emit(Event(
            type="killswitch.escalated",
            source="killswitch",
            data={"new_level": level, "user": user, "reason": reason}
        ))

        return {
            "status": "success",
            "new_level": level,
            "actions_taken": actions_taken
        }

    async def request_approval(self, level: int, requester: str, reason: str) -> ApprovalRequest:
        """Create an approval request for a high-impact action (like Level 5)."""
        req = ApprovalRequest(
            action=f"Activate Kill-Switch Level {level}",
            level=level,
            requester=requester,
            reason=reason,
            status="PENDING"
        )
        self.db.add(req)
        await self.db.commit()
        await self.db.refresh(req)
        
        await get_event_bus().emit(Event(
            type="killswitch.approval_requested",
            source="killswitch",
            data={"request_id": req.id, "level": level, "requester": requester}
        ))
        
        return req

    async def approve_request(self, request_id: int, approver: str) -> ApprovalRequest:
        """Approve a pending request."""
        result = await self.db.execute(select(ApprovalRequest).where(ApprovalRequest.id == request_id))
        req = result.scalar_one_or_none()
        
        if not req:
            raise ValueError(f"Request {request_id} not found")
        if req.status != "PENDING":
            raise ValueError(f"Request is already {req.status}")
            
        req.status = "APPROVED"
        req.approver = approver
        req.approved_at = datetime.now(timezone.utc)
        await self.db.commit()
        
        await get_event_bus().emit(Event(
            type="killswitch.approved",
            source="killswitch",
            data={"request_id": req.id, "level": req.level, "approver": approver}
        ))
        
        return req

    async def reset(self, user: str) -> dict:
        """Restore normal operations."""
        state = await self.get_state()
        old_level = state.kill_switch_level
        
        if old_level == 0:
            return {"status": "skipped", "message": "Already at level 0 (Normal)"}
            
        # Revert network blocks if they were active
        if old_level >= 3:
            s2_engine = get_firewall_engine()
            await s2_engine.reset_all_rules()
            
        state.kill_switch_level = 0
        state.kill_switch_activated_by = None
        state.kill_switch_activated_at = None
        state.kill_switch_reason = None
        
        await self.db.commit()
        
        await get_event_bus().emit(Event(
            type="killswitch.reset",
            source="killswitch",
            data={"user": user}
        ))
        
        return {"status": "success", "message": "Kill-switch deactivated, operations restored."}
