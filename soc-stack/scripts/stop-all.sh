#!/bin/bash
# WCACE SOC Stack - Stop All Services

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
STACK_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Stopping WCACE SOC Stack ==="

cd "$STACK_DIR"
docker compose --profile ir --profile webapp --profile api --profile phishing --profile dns down

echo ""
echo "=== All services stopped ==="
echo ""
echo "To also remove volumes: docker compose down -v"
