# SentinelCommand

[![Status](https://img.shields.io/badge/status-beta-blue)](https://github.com/your-org/sentinelcommand)
[![Python](https://img.shields.io/badge/python-3.11%2B-brightgreen)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)

A polished cybersecurity operations platform built for real-world incident response and automation.

SentinelCommand combines a modular FastAPI backend, async data handling, built-in observability, and command-line orchestration so security teams can respond faster and automate operational workflows.

---

## 🚀 What It Does

- Manages security workflows through modular API routes
- Protects and revokes risky sessions
- Applies firewall controls and containment actions
- Verifies backup integrity and system resilience
- Detects UBA anomalies with stream processing support
- Runs simulation scenarios for incident drills
- Exposes metrics for monitoring and performance tracking

## 🎯 Core Benefits

- FastAPI-powered API with modern async execution
- Configurable via `.env` and environment variables
- Built-in metrics support with Prometheus
- CLI-driven developer experience and operations
- Production-ready packaging with setuptools
- Clear separation between core services and modules

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

## 💡 Quick Start

### Install

```bash
python -m pip install --upgrade pip
pip install -e .
```

### Configure

```powershell
copy .env.example .env
```

Edit `.env` and set production-ready values for:

- `JWT_SECRET`
- `AUDIT_HMAC_KEY`
- `DATABASE_URL`
- `SIMULATION_MODE=false`
- `LOG_LEVEL=INFO`
- `HOST` / `PORT`

Optional:

- `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`
- `KAFKA_BOOTSTRAP_SERVERS`, `KAFKA_TOPIC`, `KAFKA_GROUP_ID`
- `WEBHOOK_URL`, `WEBHOOK_TYPE`

## ▶️ Run Locally

### Development mode

```bash
python -m sentinelcommand.cli server --host 0.0.0.0 --port 8000 --reload
```

### Production mode

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

> Use a real database backend in production instead of SQLite.

## 🧰 CLI Commands

The package exposes a top-level CLI:

```bash
sentinelcommand --help
```

Start the API:

```bash
sentinelcommand server
```

Each module also provides its own CLI entry points for specialized workflows.

## 🔍 Health & Monitoring

- `GET /health` — readiness and health probe
- Prometheus metrics enabled by default when configured

## 🛡️ Security Reminder

- Do not use default secrets in production
- Rotate `JWT_SECRET` and `AUDIT_HMAC_KEY` regularly
- Set `SIMULATION_MODE=false` for live deployments
- Protect log and database files with proper permissions

## 🧪 Development & Testing

Install dev dependencies:

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

## 📦 Packaging

Build distributables:

```bash
python -m build
```

## ✅ Deployment Checklist

- [ ] `DATABASE_URL` points at PostgreSQL, MySQL, or other managed DB
- [ ] Secrets are stored securely, not in source control
- [ ] HTTPS is enabled for external traffic
- [ ] Metrics and logs are monitored
- [ ] `SIMULATION_MODE=false` for production

## 📜 License

MIT License
