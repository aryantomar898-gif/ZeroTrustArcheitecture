# SentinelCommand

SentinelCommand is a unified cybersecurity operations platform built with FastAPI. It provides modular tooling for incident containment, session revocation, firewall enforcement, backup verification, UBA anomaly detection, simulation, and observability.

## Key Features

- API-first architecture with FastAPI
- Modular security workflows and orchestration
- Async-first persistence with SQLAlchemy + aiosqlite
- JWT authentication and audit-ready configuration
- Metrics support with Prometheus
- Extensible CLI for server and module operations
- Static dashboard served from built-in UI assets

## Project Structure

- `main.py` — FastAPI application entry point
- `sentinelcommand/cli.py` — unified CLI entry point and commands
- `sentinelcommand/core/` — configuration, auth, database, metrics, and shared services
- `sentinelcommand/modules/` — security modules and corresponding routes, schemas, and engines
- `data/` — runtime data storage
- `logs/` — runtime logs

## Getting Started

### Requirements

- Python 3.11 or newer
- `pip` package manager

### Install

```bash
python -m pip install --upgrade pip
pip install -e .
```

### Configuration

Copy the sample environment file and customize the settings for your deployment:

```bash
copy .env.example .env
```

Update these values before deploying to production:

- `JWT_SECRET`
- `AUDIT_HMAC_KEY`
- `DATABASE_URL`
- `SIMULATION_MODE=false`
- `LOG_LEVEL=INFO`
- `HOST` / `PORT`

Optional integrations:

- Azure AD via `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`
- Kafka via `KAFKA_BOOTSTRAP_SERVERS`, `KAFKA_TOPIC`, `KAFKA_GROUP_ID`
- Webhooks via `WEBHOOK_URL`, `WEBHOOK_TYPE`

## Run the Application

### Development

```bash
python -m sentinelcommand.cli server --host 0.0.0.0 --port 8000 --reload
```

or with Uvicorn directly:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### Production

For production use a process manager and a dedicated ASGI server. Example:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

Use a managed database instead of SQLite for scale and reliability.

## CLI Usage

The project exposes a top-level CLI command after installation:

```bash
sentinelcommand --help
```

Start the API server:

```bash
sentinelcommand server
```

Module commands are registered under the CLI and can be discovered via help.

## Health and Observability

- `GET /health` — health-check endpoint
- Metrics are enabled by default and exposed via the metrics router when configured

## Security Notes

- Never use default credentials or development secrets in production.
- Rotate `JWT_SECRET` and `AUDIT_HMAC_KEY` to strong random values.
- Disable `SIMULATION_MODE` in live production deployments.
- Ensure database files and logs are protected by appropriate filesystem permissions.

## Development and Testing

Install dev dependencies:

```bash
pip install -e .[dev]
```

Run tests:

```bash
pytest
```

Linting:

```bash
ruff check .
```

## Packaging

This project is packaged with setuptools. Build source and wheel distributions with:

```bash
python -m build
```

## Recommended Production Practices

- Use `DATABASE_URL` pointing to a production-grade database such as PostgreSQL
- Configure secrets through environment variables or secure secret management
- Run behind a reverse proxy / load balancer
- Enable HTTPS/TLS for all external traffic
- Monitor logs and metrics continuously

## License

MIT License
