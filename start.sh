#!/usr/bin/env bash
set -euo pipefail

HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8000}"
WORKERS="${WORKERS:-1}"

echo "Starting Binary Analysis API on ${HOST}:${PORT} (workers=${WORKERS})..."

exec uvicorn api.main:app \
    --host "${HOST}" \
    --port "${PORT}" \
    --workers "${WORKERS}"
