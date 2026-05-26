"""
S7: FastAPI routes for Ransomware Simulation.
Includes WebSocket for real-time dashboard updates.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect

from sentinelcommand.core.auth import get_current_user, require_role
from sentinelcommand.core.models import User, UserRole
from sentinelcommand.modules.simulation.engine import SimulationEngine
from sentinelcommand.modules.simulation.scenarios import SCENARIOS
from sentinelcommand.modules.simulation.schemas import (
    StartSimulationRequest,
    ResponseActionRequest,
    SimulationStateResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/simulation", tags=["S7: Simulation"])

# Connection manager for WebSockets
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict[str, Any]):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"WebSocket broadcast error: {e}")

manager = ConnectionManager()


@router.get("/scenarios")
async def list_scenarios(current_user: User = Depends(get_current_user)):
    """List available simulation scenarios."""
    return [
        {
            "id": s.id, 
            "name": s.name, 
            "description": s.description, 
            "duration_minutes": s.duration_minutes
        }
        for s in SCENARIOS.values()
    ]


@router.get("/state", response_model=SimulationStateResponse)
async def get_state(current_user: User = Depends(get_current_user)):
    """Get current simulation state."""
    engine = SimulationEngine.get_instance()
    return engine.get_state()


@router.post("/start")
async def start_simulation(
    request: StartSimulationRequest,
    current_user: User = Depends(require_role(UserRole.MANAGER, UserRole.CISO, UserRole.ADMIN)),
):
    """Start a new simulation scenario."""
    engine = SimulationEngine.get_instance()
    try:
        result = await engine.start(request.scenario_id)
        await manager.broadcast({"event": "simulation_started", "data": result})
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/stop")
async def stop_simulation(
    current_user: User = Depends(require_role(UserRole.MANAGER, UserRole.CISO, UserRole.ADMIN)),
):
    """Stop active simulation."""
    engine = SimulationEngine.get_instance()
    result = await engine.stop()
    await manager.broadcast({"event": "simulation_stopped", "data": result})
    return result


@router.post("/action")
async def submit_response_action(
    request: ResponseActionRequest,
    current_user: User = Depends(get_current_user),
):
    """Submit a response action to be scored by the simulation."""
    engine = SimulationEngine.get_instance()
    result = await engine.evaluate_response(request.action_type)
    
    if result.get("points", 0) > 0:
        await manager.broadcast({"event": "score_update", "data": result})
        
    return result


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time simulation updates.
    In a real app, we would authenticate this connection via token.
    """
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive, wait for client pings
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)
