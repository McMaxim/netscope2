#!/bin/sh
set -e

if [ -f /app/xray ]; then
    echo "[netscope] Starting xray (DE proxy on socks5://127.0.0.1:10808)..."
    /app/xray run -config /app/xray-de.json &
    sleep 1
fi

echo "[netscope] Starting FastAPI..."
exec uvicorn main:app --host 0.0.0.0 --port 8000
