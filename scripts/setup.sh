#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
[ -f .env ] || { cp .env.example .env; echo "Created .env - set SSF_ADMIN_KEY"; }
echo "Done. Run: scripts/run.sh"
