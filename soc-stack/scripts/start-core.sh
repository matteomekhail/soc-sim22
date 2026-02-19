#!/bin/bash
# WCACE SOC Stack - Start Core Services

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
STACK_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Starting WCACE SOC Core Stack ==="

cd "$STACK_DIR"
docker compose up -d wazuh-indexer wazuh-manager wazuh-dashboard suricata loki promtail grafana

echo ""
echo "=== Services Starting ==="
echo ""
echo "Wait ~60 seconds for all services to initialize, then access:"
echo "  Wazuh Dashboard:  https://localhost:5601  (admin/SecretPassword)"
echo "  Grafana:          http://localhost:3000   (admin/admin)"
echo "  Wazuh API:        https://localhost:55000"
echo "  Loki:             http://localhost:3100"
echo ""
echo "Check status: docker compose ps"
