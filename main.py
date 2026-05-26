"""
SentinelCommand main FastAPI application entry point.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import os

from sentinelcommand.core.config import get_settings
from sentinelcommand.core.database import init_db, close_db, async_session_factory
from sentinelcommand.core.auth import create_default_admin
from sentinelcommand.core.metrics import metrics_router, app_info

# Import module routers
from sentinelcommand.modules.session_revoke.routes import router as s1_router
from sentinelcommand.modules.firewall.routes import router as s2_router
from sentinelcommand.modules.backup_verify.routes import router as s3_router
from sentinelcommand.modules.killswitch.routes import router as s4_router
from sentinelcommand.modules.uba_anomaly.routes import router as s5_router
from sentinelcommand.modules.simulation.routes import router as s7_router
from sentinelcommand.modules.uba_production.routes import router as s8_router
from sentinelcommand.modules.syslog_monitor.routes import router as s10_router

_settings = get_settings()

# Configure logging
logging.basicConfig(
    level=getattr(logging, _settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle management."""
    logger.info(f"Starting {_settings.APP_NAME} v{_settings.APP_VERSION}")
    
    # Initialize database
    await init_db()
    
    # Create default admin user
    async with async_session_factory() as db:
        admin = await create_default_admin(db)
        if admin:
            logger.info("Default admin user created (admin/admin). Change password immediately!")
            
    yield
    
    # Shutdown
    logger.info("Shutting down...")
    await close_db()


app = FastAPI(
    title=_settings.APP_NAME,
    version=_settings.APP_VERSION,
    description="Unified Cybersecurity Operations Platform",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
if _settings.METRICS_ENABLED:
    app.include_router(metrics_router)

app.include_router(s1_router)
app.include_router(s2_router)
app.include_router(s3_router)
app.include_router(s4_router)
app.include_router(s5_router)
app.include_router(s7_router)
app.include_router(s8_router)
app.include_router(s10_router)


# Mount Static Files for Dashboard
static_dir = os.path.join(os.path.dirname(__file__), "sentinelcommand", "static")
if os.path.exists(static_dir):
    app.mount("/css", StaticFiles(directory=os.path.join(static_dir, "css")), name="css")
    app.mount("/js", StaticFiles(directory=os.path.join(static_dir, "js")), name="js")
    
    @app.get("/")
    async def serve_dashboard():
        return FileResponse(os.path.join(static_dir, "index.html"))

@app.get("/health", tags=["System"])
async def health_check():
    """System health check endpoint."""
    return {
        "status": "ok",
        "version": _settings.APP_VERSION,
        "simulation_mode": _settings.SIMULATION_MODE,
    }


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler for unexpected errors."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred."},
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=_settings.HOST, port=_settings.PORT, reload=True)
