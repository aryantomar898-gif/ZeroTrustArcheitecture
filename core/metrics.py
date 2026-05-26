"""
Prometheus metrics for platform observability.
Exposes counters, gauges, and histograms for security operations.
"""

from __future__ import annotations

from prometheus_client import (
    Counter,
    Gauge,
    Histogram,
    Info,
    generate_latest,
    CONTENT_TYPE_LATEST,
)
from fastapi import APIRouter, Response

from sentinelcommand.core.config import get_settings

_settings = get_settings()

# ── Counters ─────────────────────────────────────────────────────────

alerts_total = Counter(
    "sentinelcommand_alerts_total",
    "Total alerts generated",
    ["module", "severity"],
)

sessions_revoked_total = Counter(
    "sentinelcommand_sessions_revoked_total",
    "Total user sessions revoked",
    ["department"],
)

firewall_actions_total = Counter(
    "sentinelcommand_firewall_actions_total",
    "Total firewall rule changes",
    ["action"],
)

backup_verifications_total = Counter(
    "sentinelcommand_backup_verifications_total",
    "Total backup verifications performed",
    ["result"],
)

playbook_executions_total = Counter(
    "sentinelcommand_playbook_executions_total",
    "Total playbook executions",
    ["playbook", "status"],
)

killswitch_activations_total = Counter(
    "sentinelcommand_killswitch_activations_total",
    "Total kill-switch activations",
    ["level"],
)

login_attempts_total = Counter(
    "sentinelcommand_login_attempts_total",
    "Total login attempts",
    ["result"],
)

# ── Gauges ───────────────────────────────────────────────────────────

active_connections = Gauge(
    "sentinelcommand_active_websocket_connections",
    "Currently active WebSocket connections",
)

kill_switch_level = Gauge(
    "sentinelcommand_killswitch_current_level",
    "Current kill-switch level (0-5)",
)

active_alerts = Gauge(
    "sentinelcommand_active_alerts",
    "Number of unresolved alerts",
    ["severity"],
)

uba_monitored_users = Gauge(
    "sentinelcommand_uba_monitored_users",
    "Number of users with active UBA baselines",
)

# ── Histograms ───────────────────────────────────────────────────────

detection_latency = Histogram(
    "sentinelcommand_detection_latency_seconds",
    "Time from event ingestion to alert generation",
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
)

api_request_duration = Histogram(
    "sentinelcommand_api_request_duration_seconds",
    "API request processing time",
    ["method", "endpoint"],
    buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)

playbook_duration = Histogram(
    "sentinelcommand_playbook_duration_seconds",
    "Playbook execution duration",
    ["playbook"],
)

# ── Info ─────────────────────────────────────────────────────────────

app_info = Info(
    "sentinelcommand",
    "SentinelCommand application information",
)
app_info.info({
    "version": _settings.APP_VERSION,
    "simulation_mode": str(_settings.SIMULATION_MODE),
})


# ── Metrics Endpoint ─────────────────────────────────────────────────

metrics_router = APIRouter(tags=["Metrics"])


@metrics_router.get("/metrics")
async def prometheus_metrics():
    """Expose Prometheus metrics."""
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )
