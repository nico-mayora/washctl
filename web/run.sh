#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
    .venv/bin/pip install fastapi uvicorn httpx
fi

PORT="${1:-8420}"
echo "Starting washer control at http://localhost:$PORT"
exec .venv/bin/python -m uvicorn server:app --host 0.0.0.0 --port "$PORT" --reload
