#!/bin/bash
set -e

# Use the prebuilt venv binaries directly: no uv sync/cache writes at runtime,
# which also keeps this working as the non-root container user.
VENV_BIN="${VENV_BIN:-/app/.venv/bin}"

echo "Upgrading database..."
"$VENV_BIN/alembic" upgrade head

echo "Starting FastAPI server (gunicorn + uvicorn workers)..."
exec "$VENV_BIN/gunicorn" main:app \
  --workers "${WEB_CONCURRENCY:-4}" \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind "${API_HOST:-0.0.0.0}:${API_PORT:-5000}" \
  --timeout 120 \
  --access-logfile - \
  --error-logfile -
