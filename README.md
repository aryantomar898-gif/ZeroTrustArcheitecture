# 🛡️ SENTINEL Platform
### Advanced Security Operations & Incident Response Platform

> A production-grade, open-source cybersecurity platform integrating session management, firewall orchestration, backup verification, zero-trust controls, behavioral analytics, SOAR automation, and incident simulation — all in one unified system.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green.svg)](https://fastapi.tiangolo.com/)
[![React 18](https://img.shields.io/badge/React-18+-61DAFB.svg)](https://react.dev/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg)](https://docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📋 Table of Contents

- [Architecture Overview](#architecture-overview)
- [Modules](#modules)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     SENTINEL Platform                        │
├────────────┬────────────┬────────────┬────────────┬─────────┤
│   S1       │    S2      │    S3      │    S4      │   S5    │
│ Session    │ Firewall   │  Backup    │ Kill-Switch│   UBA   │
│ Revocation │ Manager    │ Verifier   │    API     │ Engine  │
├────────────┴────────────┴────────────┴────────────┴─────────┤
│                  S9: SOAR Orchestration Engine               │
├─────────────────────────────────────────────────────────────┤
│        S8: Production UBA Microservice (Kafka/EventHub)      │
├─────────────────────────────────────────────────────────────┤
│              S7: Simulation & Training Platform              │
├─────────────────────────────────────────────────────────────┤
│          Unified Web Dashboard  │  REST API Gateway          │
└─────────────────────────────────────────────────────────────┘
```

---

## 🧩 Modules

| ID | Module | Description |
|----|--------|-------------|
| S1 | Session Revocation CLI | Revoke all Microsoft Entra ID sessions via OAuth 2.0 |
| S2 | Firewall Manager | iptables-based ransomware containment & microsegmentation |
| S3 | Backup Hash Verifier | SHA-256 integrity verification with HTML/JSON reports |
| S4 | Zero-Trust Kill-Switch API | Graded 5-level network lockdown REST API |
| S5 | UBA Engine | Baseline anomaly detection with webhook alerts |
| S7 | Simulation Platform | Gamified ransomware incident response training |
| S8 | UBA Production Service | Kafka-powered ML behavioral analytics microservice |
| S9 | SOAR Orchestrator | YAML playbook-driven security automation |

---

## ⚡ Quick Start

### Using Docker Compose (Recommended)

```bash
git clone https://github.com/your-org/sentinel-platform.git
cd sentinel-platform

# Copy and configure environment
cp .env.example .env
nano .env   # Fill in your credentials

# Launch all services
docker-compose up -d

# Access dashboard
open http://localhost:3000
```

### Manual Setup

```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn api.main:app --reload --port 8000

# Frontend (separate terminal)
cd frontend
npm install
npm run dev
```

---

## 🔧 Installation

### Prerequisites

- Python 3.11+
- Node.js 18+
- Docker & Docker Compose
- Linux (for S2 iptables module — requires root)
- Azure App Registration (for S1 — optional)
- Kafka or Azure Event Hub (for S8 — optional)

### Environment Variables

```bash
# Azure / Microsoft Entra ID (S1, S4)
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret

# Database
DATABASE_URL=sqlite:///./sentinel.db

# Kafka (S8 - optional)
KAFKA_BOOTSTRAP_SERVERS=localhost:9092
KAFKA_TOPIC=security-events

# Webhooks (S5)
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
TEAMS_WEBHOOK_URL=https://...

# Security
JWT_SECRET_KEY=change-this-in-production
CISO_EMAIL=ciso@yourorg.com

# Prometheus (S8)
PROMETHEUS_PORT=9090
```

---

## 📁 Project Structure

```
sentinel-platform/
├── backend/
│   ├── api/
│   │   ├── main.py              # FastAPI application entry point
│   │   ├── auth.py              # JWT authentication & RBAC
│   │   ├── routes/              # API route handlers
│   │   └── middleware.py        # Logging, CORS, rate limiting
│   ├── modules/
│   │   ├── s1_session/          # Session revocation (Entra ID)
│   │   ├── s2_firewall/         # iptables manager
│   │   ├── s3_backup/           # Backup hash verifier
│   │   ├── s4_killswitch/       # Zero-trust kill-switch
│   │   ├── s5_uba/              # User behavior analytics
│   │   ├── s7_simulation/       # Incident simulation engine
│   │   ├── s8_uba_prod/         # Production UBA microservice
│   │   └── s9_soar/             # SOAR orchestrator
│   ├── playbooks/               # YAML playbook definitions
│   ├── connectors/              # External service connectors
│   └── db/                      # Database models & migrations
├── frontend/
│   ├── src/
│   │   ├── components/          # Reusable UI components
│   │   ├── pages/               # Dashboard pages
│   │   ├── hooks/               # Custom React hooks
│   │   └── utils/               # Utilities & API client
│   └── public/
├── cli/
│   └── sentinel_cli.py          # Unified CLI entry point
├── docker/
│   ├── Dockerfile.backend
│   ├── Dockerfile.frontend
│   └── docker-compose.yml
├── grafana/
│   └── dashboards/              # Pre-built Grafana dashboards
├── tests/
│   ├── test_s1.py
│   ├── test_s4.py
│   └── ...
├── docs/
│   └── api.md
├── .env.example
└── requirements.txt
```

---

## 🔒 Security Considerations

- All API endpoints require JWT authentication
- Level 5 kill-switch requires dual-approval (CISO + secondary approver)
- Audit logs are cryptographically signed (HMAC-SHA256)
- iptables module requires root — use with caution in production
- Azure credentials should use Managed Identity in cloud deployments
- Never commit `.env` to version control

---

## 📊 Monitoring

- **Prometheus**: `http://localhost:9090` — metrics from S8
- **Grafana**: `http://localhost:3001` — pre-built security dashboards
- **API Docs**: `http://localhost:8000/docs` — Swagger UI

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-module`)
3. Commit your changes (`git commit -m 'Add new detection rule'`)
4. Push to the branch (`git push origin feature/new-module`)
5. Open a Pull Request

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built for security professionals, by security professionals.*
