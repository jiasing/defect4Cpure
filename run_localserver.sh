#!/usr/bin/env bash
# Installs missing Python deps and starts the defects4c API server inside the container.
# Usage: bash run_localserver.sh

set -e

CONTAINER="my_defects4c"

echo "[1/3] Installing Python dependencies..."
docker exec "$CONTAINER" pip3 install -q \
    "uvicorn[standard]" \
    fastapi \
    pandas \
    jinja2 \
    jmespath \
    redis

echo "[2/3] Starting uvicorn server on port 80..."
docker exec -d "$CONTAINER" bash -lc \
    'cd /src && uvicorn new_main:app --host 0.0.0.0 --port 80 > /tmp/uvicorn.log 2>&1'

echo "[3/3] Waiting for server to be ready..."
for i in $(seq 1 15); do
    if docker exec "$CONTAINER" curl -sf http://127.0.0.1:80/list_defects_bugid > /dev/null 2>&1; then
        echo "Server is up at http://127.0.0.1:11111"
        exit 0
    fi
    sleep 1
done

echo "Server did not respond in time. Check logs:"
echo "  docker exec $CONTAINER cat /tmp/uvicorn.log"
exit 1
