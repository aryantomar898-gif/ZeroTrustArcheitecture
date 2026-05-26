# SentinelCommand

[![Status](https://img.shields.io/badge/status-beta-blue)](https://github.com/your-org/sentinelcommand)
[![Python](https://img.shields.io/badge/python-3.11%2B-brightgreen)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)

SentinelCommand is a unified cybersecurity operations platform built to help security operations teams respond faster, enforce containment actions, and verify system integrity.

It combines:
- A modular FastAPI backend
- A CLI for operational workflows
- Async persistence and metrics
- Built-in governance controls for incident response

---

## 🚀 What SentinelCommand Enables

SentinelCommand is designed to support real-world security operations by providing:

- **Incident containment** through firewall and kill-switch controls
- **Session revocation** for compromised or inactive accounts
- **Backup verification** to ensure recovery readiness
- **User behavior analytics** to detect anomalous activity
- **Simulation scenarios** for tabletop exercise preparation
- **Observability** through health and metrics endpoints

## 🧩 Architecture Overview

The application is organized into two major layers:

1. **Core services** (`sentinelcommand/core/`)
   - Configuration via `pydantic-settings`
   - Async database initialization and session management
   - Authentication and default admin provisioning
   - Metrics and health endpoint integration

2. **Modules** (`sentinelcommand/modules/`)
   - Each module exposes REST routes and CLI helpers
   - Modules are designed to be extended independently
   - Current modules include: `session_revoke`, `firewall`, `backup_verify`, `killswitch`, `uba_anomaly`, `simulation`, `syslog_monitor`, and `uba_production`

## 📁 Project Layout

```text
main.py
sentinelcommand/
├── cli.py
├── core/
│   ├── auth.py
│   ├── config.py
│   ├── database.py
│   ├── metrics.py
│   └── ...
└── modules/
    ├── backup_verify/
    ├── firewall/
    ├── killswitch/
    ├── session_revoke/
    ├── simulation/
    ├── syslog_monitor/
    ├── uba_anomaly/
    └── uba_production/
```

---

## 🔧 Features and Commands

The project bundles a CLI entrypoint and module-specific operations. After installation, use:

```bash
sentinelcommand --help
```

### Core CLI

```bash
sentinelcommand server --host 0.0.0.0 --port 8000 --reload
```

This command starts the FastAPI service and loads all registered module routers.

### Session Revocation (`session-revoke`)

Use the Session Revocation module to manage Microsoft Entra ID user sessions.

- `sentinelcommand session-revoke list-users` — list users and account status
- `sentinelcommand session-revoke revoke-user <user_id>` — revoke a single user session
- `sentinelcommand session-revoke revoke-all` — revoke sessions for all users, optionally by department

This module is appropriate for emergency access control and rapid remediation in a compromised tenant.

### Firewall Management (`firewall`)

The firewall module provides ransomware containment and network microsegmentation controls.

- `sentinelcommand firewall menu` — interactive firewall management menu
- `sentinelcommand firewall block-smb` — block SMB ports immediately
- `sentinelcommand firewall microsegment` — apply emergency subnet isolation
- `sentinelcommand firewall reset` — reset all firewall rules
- `sentinelcommand firewall status` — show current firewall rule state

Use these commands for rapid containment during ransomware or lateral movement events.

### Kill-Switch (`killswitch`)

The kill-switch module lets you raise and lower trust levels globally.

- `sentinelcommand killswitch status` — view current kill-switch level
- `sentinelcommand killswitch activate --level <1-5> --reason <reason>` — activate an emergency containment level
- `sentinelcommand killswitch reset` — reset kill-switch back to level 0

This is useful for enforcing broad protective posture changes across the environment.

### Backup Verification (`backup-verify`)

Backup verification helps ensure recovery artifacts are intact and uncompromised.

- `sentinelcommand backup-verify hash <file_path>` — calculate a file hash
- `sentinelcommand backup-verify check <file_path> --manifest <manifest.json>` — verify a file against a hash manifest
- `sentinelcommand backup-verify batch <csv_path>` — verify a list of files and optionally generate an HTML report
- `sentinelcommand backup-verify generate-manifest <directory>` — generate a hash manifest for a folder

This module helps prove backup integrity during incident recovery or audits.

### UBA Anomaly Detection (`uba`)

User Behavior Analytics detects anomalous events against baseline models.

- `sentinelcommand uba ingest <file_path>` — ingest historical logs to build baseline behavior
- `sentinelcommand uba analyze <json_event>` — analyze a single event in real time

This enables threat detection and continuous monitoring of unusual activity.

---

## ⚙️ How to Implement SentinelCommand in Industry

SentinelCommand is best deployed as an integrated security operations service rather than an isolated script.

### 1. Use environment-based configuration

Store secrets and runtime settings in environment variables or secret management solutions. Do not commit `.env` to source control.

Key production settings:

- `DATABASE_URL` — production-grade database connection string
- `JWT_SECRET` — strong, random JWT signing secret
- `AUDIT_HMAC_KEY` — secure key for audit integrity
- `SIMULATION_MODE=false` — disable simulation mode in live environments
- `LOG_LEVEL=INFO` — use structured logging and avoid debug noise

### 2. Deploy with a robust ASGI server

Use `uvicorn` or a process manager such as Gunicorn with Uvicorn workers.

Example production startup:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

For high availability, run behind a load balancer and route traffic through an application gateway.

### 3. Choose a production-ready database

Production deployments should use PostgreSQL, MySQL, or other managed databases instead of SQLite.

Example `DATABASE_URL`:

```text
postgresql+asyncpg://user:password@db-host:5432/sentinelcommand
```

### 4. Harden authentication and access control

- Rotate JWT and audit secrets regularly
- Secure API access behind a proxy or WAF
- Use HTTPS/TLS for all external traffic
- Restrict admin CLI access to authorized personnel

### 5. Add monitoring and observability

- Collect metrics from the built-in metrics endpoints
- Integrate with Prometheus and Grafana
- Send logs to a centralized logging system
- Monitor health via `GET /health`

### 6. Define operational runbooks

For adoption in an enterprise setting, document workflows for:

- Incident detection and escalation
- Ransomware containment with `firewall` and `killswitch`
- Session revocation and access cleanup
- Backup validation and recovery readiness
- Anomaly triage using UBA alerts

### 7. Automate with CI/CD

Build, test, and package the application using CI pipelines.

Recommended pipeline steps:

- Install dependencies
- Run linting with `ruff`
- Execute test suite with `pytest`
- Build and publish distributable artifacts
- Deploy container images or packaged artifacts to staging and production

---

## 📦 Installation

### Requirements

- Python 3.11 or newer
- `pip`

### Install locally

```bash
python -m pip install --upgrade pip
pip install -e .
```

### Configure

```powershell
copy .env.example .env
```

Edit `.env` and change production values.

---

## ▶️ Running the Service

### Development mode

```bash
python -m sentinelcommand.cli server --host 0.0.0.0 --port 8000 --reload
```

### Production mode

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

### Health and metrics

- `GET /health` — health probe response
- Metrics are exposed when `METRICS_ENABLED=true`

---

## 🧪 Development & Testing

Install development dependencies:

```bash
pip install -e .[dev]
```

Run tests:

```bash
pytest
```

Run linting:

```bash
ruff check .
```

---

## ✅ Industry Checklist

- [ ] Use managed database service for production
- [ ] Store secrets securely
- [ ] Disable simulation mode in production
- [ ] Secure API with HTTPS and network controls
- [ ] Monitor logs and metrics continuously
- [ ] Create operational runbooks for containment and recovery

---

## 🧪 Demo Guide

A dedicated demo guide is available in [`DEMO.md`](DEMO.md) with step-by-step commands, example demo data, and a safe demo flow.
## 📜 License

MIT License
