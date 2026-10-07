#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[ -d .venv ] && . .venv/bin/activate
[ -f .env ] && { set -a; . ./.env; set +a; }
exec python -m ssf.app
