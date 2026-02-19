#!/bin/bash
# WCACE SOC Stack - Initial Setup
# Pull all Docker images and configure initial state

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
STACK_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== WCACE SOC Stack Setup ==="
echo ""

# Check Docker
if ! command -v docker &>/dev/null; then
    echo "[ERROR] Docker is not installed. Please install Docker Desktop."
    exit 1
fi

if ! docker info &>/dev/null; then
    echo "[ERROR] Docker daemon is not running. Please start Docker Desktop."
    exit 1
fi

echo "[*] Pulling core images..."
docker compose -f "$STACK_DIR/docker-compose.yml" pull wazuh-indexer wazuh-manager wazuh-dashboard suricata loki promtail grafana

echo ""
echo "[*] Core images pulled successfully."
echo ""
echo "[*] To pull on-demand images:"
echo "    docker compose -f $STACK_DIR/docker-compose.yml --profile ir pull       # TheHive"
echo "    docker compose -f $STACK_DIR/docker-compose.yml --profile webapp pull   # DVWA"
echo "    docker compose -f $STACK_DIR/docker-compose.yml --profile dns pull      # CoreDNS"
echo ""

# Create sandbox directories for FIM monitoring
mkdir -p /tmp/wcace-sandbox
echo "[*] Created /tmp/wcace-sandbox for File Integrity Monitoring"

echo ""
echo "=== Setup Complete ==="
echo "Run ./start-core.sh to start the SOC stack"
