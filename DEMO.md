# SentinelCommand Demo Guide

This guide walks through a live demo of the SentinelCommand platform. It is designed for a safe local demonstration using the built-in CLI and API.

## 1. Prerequisites

- Python 3.11 or newer
- Windows PowerShell or another terminal
- Project dependencies installed

### Install dependencies

```powershell
python -m pip install --upgrade pip
pip install -e .
```

## 2. Environment setup

Copy the sample environment file and configure it for demo mode:

```powershell
copy .env.example .env
```

Recommended demo settings in `.env`:

- `SIMULATION_MODE=true`
- `LOG_LEVEL=DEBUG`
- Keep `DATABASE_URL` as SQLite for local demos
- Set `JWT_SECRET` and `AUDIT_HMAC_KEY` to placeholder values for demo only

## 3. Start the service

Run the FastAPI server in one terminal:

```powershell
python -m sentinelcommand.cli server --host 0.0.0.0 --port 8000 --reload
```

Then open these URLs in a browser:

- `http://localhost:8000/health`
- `http://localhost:8000/docs`

## 4. Confirm the service is healthy

In a second terminal, run:

```powershell
curl http://localhost:8000/health
```

Expected response contains:

- `status: ok`
- `version`
- `simulation_mode: true`

## 5. Demo sequence for all tools

This section shows one command for each module.

### 5.1 Core service

```powershell
sentinelcommand --help
sentinelcommand server --help
```

Show that the server CLI is available and the `server` command starts the app.

### 5.2 Session Revocation

List users:

```powershell
sentinelcommand session-revoke list-users
```

Revoke a single user session (replace `<user_id>` with a valid ID from the list):

```powershell
sentinelcommand session-revoke revoke-user <user_id>
```

Run an all-user revoke in demo mode:

```powershell
sentinelcommand session-revoke revoke-all --confirm
```

> Note: In an actual enterprise environment, this module is used for rapid tenant cleanup when an account is compromised.

### 5.3 Firewall management

Show current firewall status:

```powershell
sentinelcommand firewall status
```

Block SMB ports immediately:

```powershell
sentinelcommand firewall block-smb
```

Apply emergency microsegmentation:

```powershell
sentinelcommand firewall microsegment
```

Reset firewall rules back to default:

```powershell
sentinelcommand firewall reset
```

For an interactive demo:

```powershell
sentinelcommand firewall menu
```

### 5.4 Kill-Switch

View current kill-switch level:

```powershell
sentinelcommand killswitch status
```

Activate a containment level:

```powershell
sentinelcommand killswitch activate --level 3 --reason "Demo containment"
```

Reset the kill-switch:

```powershell
sentinelcommand killswitch reset
```

### 5.5 Backup Verification

Generate a sample manifest for a directory:

```powershell
sentinelcommand backup-verify generate-manifest . --algo sha256
```

Calculate a hash for a file:

```powershell
sentinelcommand backup-verify hash README.md --algo sha256
```

Verify a file using a manifest:

```powershell
sentinelcommand backup-verify check README.md --manifest manifest.json
```

Batch verify a CSV list of files:

```powershell
sentinelcommand backup-verify batch demo_files.csv
```

### 5.6 UBA anomaly detection

Ingest a sample event dataset:

```powershell
sentinelcommand uba ingest demo_events.json
```

Analyze a single JSON event:

```powershell
sentinelcommand uba analyze "{\"user_id\":\"alice\",\"action\":\"login\",\"ip\":\"10.1.1.5\"}"
```

## 6. Sample demo data

For a simple demo, create these files manually or use your own sample data.

### Sample event file (`demo_events.json`)

```json
[
  {
    "user_id": "alice",
    "action": "login",
    "ip": "10.1.1.5",
    "timestamp": "2026-05-26T15:00:00Z",
    "device": "laptop-01",
    "location": "office"
  },
  {
    "user_id": "alice",
    "action": "file_access",
    "resource": "finance-report.xlsx",
    "timestamp": "2026-05-26T15:10:00Z"
  }
]
```

### Sample batch file list (`demo_files.csv`)

```csv
file_path
README.md
pyproject.toml
main.py
```

## 7. Recommended demo flow

1. Start the server and verify `GET /health`
2. Open `http://localhost:8000/docs`
3. Run `sentinelcommand session-revoke list-users`
4. Show firewall commands and run `status` + `block-smb`
5. Demonstrate kill-switch activation and reset
6. Generate a backup manifest and validate one file
7. Ingest a sample UBA dataset and analyze an event

## 8. Demo talking points for industry

- Use `simulation_mode=true` for safe trials
- Local SQLite is fine for demos, but production should use a managed database
- The CLI can be integrated into playbooks, runbooks, and incident response orchestration
- The API routes can be exposed behind enterprise gateways and monitored with Prometheus
- The platform is designed to support containment, forensic validation, and anomaly detection in one service

## 9. Cleanup after demo

- Stop the server
- Delete demo files if desired
- Remove or reset `.env` if you used temporary secrets

---

For more details, refer to `README.md` and the module-specific CLI help.
