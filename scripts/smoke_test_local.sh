#!/bin/bash
set -e

echo "Starting Local Smoke Test for Cyanide-Honeypot..."

echo "Building Docker image 'cyanide-honeypot:smoke'..."
docker build -t cyanide-honeypot:smoke .

echo "Starting container..."
CONTAINER_NAME="cyanide-smoke-test-run"
docker rm -f $CONTAINER_NAME 2>/dev/null || true

docker run -d --name $CONTAINER_NAME \
  -p 2222:2222 -p 2323:2323 -p 9090:9090 \
  -e LOG_LEVEL=DEBUG \
  -e CYANIDE_METRICS_ENABLED=true \
  -e CYANIDE_METRICS_PORT=9090 \
  -e CYANIDE_METRICS_ALLOW_REMOTE=true \
  -e CYANIDE_METRICS_TOKEN=smoke-token-123 \
  -e CYANIDE_SSH_ENABLED=true \
  -e CYANIDE_SSH_LISTEN_PORT=2222 \
  -e CYANIDE_TELNET_ENABLED=true \
  -e CYANIDE_TELNET_LISTEN_PORT=2323 \
  -e CYANIDE_USERS='[{"user": "root", "pass": "admin"}]' \
  cyanide-honeypot:smoke

trap "echo 'Cleaning up...'; docker stop $CONTAINER_NAME >/dev/null 2>&1 || true; docker rm $CONTAINER_NAME >/dev/null 2>&1 || true; exit" EXIT INT TERM

sleep 5
if [ "$(docker inspect -f '{{.State.Running}}' $CONTAINER_NAME)" != "true" ]; then
  echo "❌ Container died immediately!"
  docker logs $CONTAINER_NAME
  exit 1
fi
echo "✅ Container is running."

echo "Waiting for health check (up to 60s)..."
READY=0
for i in $(seq 1 20); do
  RESPONSE=$(curl -s --max-time 3 http://127.0.0.1:9090/health || echo "")
  if [ -n "$RESPONSE" ]; then
    if echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if d.get('status')=='healthy' else 1)" 2>/dev/null; then
      echo "✅ App is HEALTHY after ~$((i*3))s"
      READY=1
      break
    else
      echo "⏳ App responded but status not healthy: $RESPONSE"
    fi
  else
    echo "⏳ Waiting for response (attempt $i/20)..."
  fi
  sleep 3
done

if [ $READY -eq 0 ]; then
  echo "❌ Timeout: App never became healthy."
  docker logs $CONTAINER_NAME
  exit 1
fi

echo "Verifying metrics protection..."
STATS_NO_TOKEN=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:9090/stats)
if [ "$STATS_NO_TOKEN" == "401" ]; then
  echo "✅ /stats is protected (401 Unauthorized)"
else
  echo "❌ /stats is NOT protected! (Status: $STATS_NO_TOKEN)"
  exit 1
fi

STATS_WITH_TOKEN=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer smoke-token-123" http://127.0.0.1:9090/stats)
if [ "$STATS_WITH_TOKEN" == "200" ]; then
  echo "✅ /stats is accessible with token"
else
  echo "❌ /stats with token failed! (Status: $STATS_WITH_TOKEN)"
  exit 1
fi

echo "Testing SSH (2222) and Telnet (2323) sockets..."
python3 -c 'import socket; s=socket.socket(); s.settimeout(5); s.connect(("127.0.0.1", 2222)); s.close()' || (echo "❌ SSH port unreachable"; exit 1)
python3 -c 'import socket; s=socket.socket(); s.settimeout(5); s.connect(("127.0.0.1", 2323)); s.close()' || (echo "❌ Telnet port unreachable"; exit 1)
echo "✅ TCP ports are open."

echo "Testing SSH Login and Command Execution..."
export SSHPASS="admin"
SSH_OUTPUT=$(sshpass -e ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -p 2222 root@127.0.0.1 "echo SMOKE_TEST_OK" 2>&1 || true)
echo "SSH Output: $SSH_OUTPUT"
if [[ "$SSH_OUTPUT" == *"SMOKE_TEST_OK"* ]]; then
  echo "✅ SSH login functional!"
else
  echo "❌ SSH login check failed!"
  docker logs $CONTAINER_NAME
  exit 1
fi

echo "🚀 ALL SMOKE TESTS PASSED!"
