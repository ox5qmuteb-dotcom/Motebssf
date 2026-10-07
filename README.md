# SSF – Security System Framework (Motebssf)

Flask-based security platform: vulnerability scanning, secret detection, threat monitoring,
role-based access control with audit log, security reports and a web dashboard.

## Quick start
```bash
scripts/setup.sh && scripts/run.sh     # http://127.0.0.1:8080
# or
cp .env.example .env && docker compose up --build
```
Set `SSF_ADMIN_KEY`; if unset a key is generated and logged once at first start.
Open the dashboard and enter the API key. Run tests: `pytest`.

## Configuration
`config/ssf.json` (path via `SSF_CONFIG`), overridden by env vars: `SSF_DB_PATH`, `SSF_SCAN_ROOT`,
`SSF_LOG_LEVEL`, `SSF_LOG_FILE`, `SSF_ADMIN_KEY`, `SSF_ALERT_WEBHOOK` (https only),
`SSF_EXTERNAL_TOOLS`, `SSF_TOOL_TIMEOUT`, `SSF_BRUTEFORCE_THRESHOLD`, `SSF_BRUTEFORCE_WINDOW`, `SSF_HOST`, `SSF_PORT`.

## Features
- **Vulnerability scanner** – built-in Python/JS rules plus bandit, safety and semgrep when installed
  (`# nosec` or `ssf:ignore` suppresses a line). Scans are confined to `SSF_SCAN_ROOT`.
- **Secret detection** – cloud keys, tokens, private keys, URL credentials, generic assignments; matches are always redacted.
- **Threat monitor** – event ingestion with SQLi/XSS/traversal/command-injection signatures, brute-force detection, log analysis.
- **Access control** – roles `admin`, `analyst`, `viewer`; hashed API keys; every request audited.
- **Reports** – JSON, HTML, text with a 0–100 score.
- **Alerting** – log, stored alerts, optional webhook.

## REST API (header `X-API-Key`)
| Method | Path | Permission |
|---|---|---|
| GET | `/api/health` | none |
| POST | `/api/scan` `{path}` / `/api/scan/secrets` `{path｜text}` | scan:run |
| GET | `/api/scans`, `/api/scans/<id>` | scan:read |
| POST | `/api/threats/events`, `/api/threats/analyze` `{log}` | threats:write |
| GET | `/api/threats/status`, `/api/threats/alerts` | threats:read |
| GET/POST | `/api/access/users`; PUT `.../<name>/role`; DELETE `.../<name>`; GET `/api/access/roles`, `/api/access/audit` | access:read / admin |
| GET | `/api/reports?scan_id=&format=json｜html｜text` | reports:read |

Production notes: run behind HTTPS reverse proxy; the Docker image uses gunicorn and a non-root user.
