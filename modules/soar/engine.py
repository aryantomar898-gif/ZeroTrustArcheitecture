"""
S9: SOAR Playbook Execution Engine.
Parses YAML playbooks and executes steps concurrently using connectors.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import yaml

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelcommand.core.config import get_settings
from sentinelcommand.core.events import Event, get_event_bus
from sentinelcommand.core.models import PlaybookExecution, PlaybookStatus
from sentinelcommand.modules.soar.connectors import get_connector

logger = logging.getLogger(__name__)
_settings = get_settings()


class SOAREngine:
    """Executes security playbooks."""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.playbooks_dir = Path(__file__).parent / "playbooks"

    def list_playbooks(self) -> list[dict]:
        """List all available YAML playbooks."""
        playbooks = []
        if not self.playbooks_dir.exists():
            return playbooks
            
        for file in self.playbooks_dir.glob("*.yaml"):
            try:
                with open(file, "r") as f:
                    data = yaml.safe_load(f)
                    playbooks.append({
                        "id": file.stem,
                        "name": data.get("name", file.stem),
                        "description": data.get("description", ""),
                    })
            except Exception as e:
                logger.error(f"Error parsing playbook {file.name}: {e}")
                
        return playbooks

    def get_playbook(self, playbook_id: str) -> dict:
        """Load a specific playbook."""
        file_path = self.playbooks_dir / f"{playbook_id}.yaml"
        if not file_path.exists():
            raise FileNotFoundError(f"Playbook not found: {playbook_id}")
            
        with open(file_path, "r") as f:
            return yaml.safe_load(f)

    async def execute_playbook(self, playbook_id: str, context: dict[str, Any], triggered_by: str) -> PlaybookExecution:
        """Start execution of a playbook."""
        playbook = self.get_playbook(playbook_id)
        steps = playbook.get("steps", [])
        
        # Create execution record
        execution = PlaybookExecution(
            playbook_name=playbook.get("name", playbook_id),
            status=PlaybookStatus.RUNNING,
            triggered_by=triggered_by,
            context=json.dumps(context),
            total_steps=len(steps),
            execution_log="[]"
        )
        self.db.add(execution)
        await self.db.commit()
        await self.db.refresh(execution)
        
        # In a real system, this would be handed off to a Celery worker.
        # Here, we run it as a background task.
        asyncio.create_task(self._run_execution_loop(execution.id, steps, context))
        
        return execution

    async def _run_execution_loop(self, execution_id: int, steps: list[dict], context: dict[str, Any]):
        """Background loop to execute steps."""
        # Need a new DB session for background task
        from sentinelcommand.core.database import async_session_factory
        
        async with async_session_factory() as db:
            execution = await db.get(PlaybookExecution, execution_id)
            if not execution:
                return
                
            log_entries = []
            
            # Inject db into context for internal connectors
            step_context = dict(context)
            step_context["db"] = db
            
            try:
                for idx, step in enumerate(steps):
                    execution.current_step = idx + 1
                    step_name = step.get("name", f"Step {idx+1}")
                    
                    # Log start
                    log_entries.append({
                        "step": idx + 1,
                        "name": step_name,
                        "status": "started",
                        "time": datetime.now(timezone.utc).isoformat()
                    })
                    await self._update_execution(db, execution, log_entries)
                    
                    # Check for approval gate
                    if step.get("require_approval", False):
                        # Pause execution logic goes here in a real app
                        # We'd set status to AWAITING_APPROVAL and exit the loop,
                        # resuming from this step upon approval.
                        logger.info(f"Playbook {execution.id} requires approval at step {idx+1}")
                    
                    # Execute action
                    action_type = step.get("action")
                    if action_type == "parallel":
                        # Run multiple actions concurrently
                        tasks = []
                        for sub in step.get("actions", []):
                            tasks.append(self._execute_single_action(sub, step_context))
                        results = await asyncio.gather(*tasks, return_exceptions=True)
                        
                        # Check for failures
                        failed = any(not getattr(r, 'success', False) for r in results if not isinstance(r, Exception))
                        has_exception = any(isinstance(r, Exception) for r in results)
                        
                        if failed or has_exception:
                            raise RuntimeError(f"Parallel step failed. Results: {results}")
                    else:
                        # Single action
                        result = await self._execute_single_action(step, step_context)
                        if not result.success:
                            raise RuntimeError(f"Step failed: {result.error}")
                            
                    # Log success
                    log_entries[-1]["status"] = "completed"
                    log_entries[-1]["end_time"] = datetime.now(timezone.utc).isoformat()
                    await self._update_execution(db, execution, log_entries)
                    
                # All steps completed
                execution.status = PlaybookStatus.COMPLETED
                execution.completed_at = datetime.now(timezone.utc)
                await self._update_execution(db, execution, log_entries)
                
                await get_event_bus().emit(Event(
                    type="soar.playbook_completed",
                    source="soar",
                    data={"execution_id": execution.id, "name": execution.playbook_name}
                ))
                
            except Exception as e:
                logger.error(f"Playbook {execution_id} failed: {e}")
                execution.status = PlaybookStatus.FAILED
                execution.completed_at = datetime.now(timezone.utc)
                if log_entries:
                    log_entries[-1]["status"] = "failed"
                    log_entries[-1]["error"] = str(e)
                await self._update_execution(db, execution, log_entries)

    async def _execute_single_action(self, step: dict, context: dict[str, Any]):
        """Execute a single connector action."""
        # e.g., "msgraph.revoke_sessions"
        action_path = step.get("action", "")
        if "." not in action_path:
            # Fallback to simulated if not specified
            connector_name = "simulated"
            action = action_path
        else:
            connector_name, action = action_path.split(".", 1)
            
        params = step.get("params", {})
        
        # Variable substitution in params (e.g., "{{ user_id }}")
        for k, v in params.items():
            if isinstance(v, str) and v.startswith("{{") and v.endswith("}}"):
                var_name = v.strip("{} ")
                params[k] = context.get(var_name, v)
                
        connector = get_connector(connector_name)
        return await connector.execute(action, params, context)

    async def _update_execution(self, db: AsyncSession, execution: PlaybookExecution, logs: list):
        """Update DB record."""
        execution.execution_log = json.dumps(logs)
        await db.commit()
