#!/bin/bash
set -e

echo "Upgrading database..."
uv run alembic upgrade head

echo "Starting FastAPI server (gunicorn + uvicorn workers)..."
exec uv run gunicorn main:app \
  --workers "${WEB_CONCURRENCY:-4}" \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind "${API_HOST:-0.0.0.0}:${API_PORT:-5000}" \
  --timeout 120 \
  --access-logfile - \
  --error-logfile -
