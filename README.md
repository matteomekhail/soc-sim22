# WCACE - 22 SOC Simulation Scenarios

Open-source Security Operations Center (SOC) simulation platform featuring 22 real-world cybersecurity scenarios. Built for Western Sydney University's CACE program.

## Overview

This project provides hands-on SOC analyst training through simulated cyber attacks and their detection using open-source tools. Each scenario includes attack simulation, detection rules, and incident response playbooks.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   SOC Stack (Docker)                │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐            │
│  │  Wazuh   │ │ Suricata │ │ Grafana  │            │
│  │ Manager  │ │   IDS    │ │  + Loki  │            │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘            │
│       │             │            │                   │
│  ┌────┴─────┐      │       ┌────┴─────┐            │
│  │  Wazuh   │      │       │ Promtail │            │
│  │ Indexer  │      │       └──────────┘            │
│  └────┬─────┘      │                                │
│  ┌────┴─────┐      │                                │
│  │  Wazuh   │      │                                │
│  │Dashboard │      │                                │
│  └──────────┘      │                                │
└─────────────────────┼────────────────────────────────┘
                      │
        ┌─────────────┴──────────────┐
        │    Attack Simulations      │
        │   (Python + wcace_lib)     │
        └────────────────────────────┘
```

## Scenarios

| # | Scenario | Tier | MITRE ATT&CK |
|---|----------|------|---------------|
| 1 | APT Deepfake CEO Fraud | 3 (Demo) | T1566, T1204 |
| 2 | Domain Spoofing & Data Theft | 2 | T1583.001, T1071 |
| 3 | Financial Transaction Fraud | 3 (Demo) | T1657, T1565 |
| 4 | Insider Threat Data Exfiltration | 1 | T1567, T1048 |
| 5 | APT Vulnerability Exploitation | 2 | T1190, T1210 |
| 6 | Dark Web Monitoring | 3 (Demo) | T1583, T1597 |
| 7 | Zero-Day & Lateral Movement | 2 | T1068, T1021 |
| 8 | Phishing & Ransomware | 1 | T1566.001, T1486 |
| 9 | Insider Data Theft | 1 | T1530, T1041 |
| 10 | APT with RAT | 2 | T1219, T1071 |
| 11 | Botnet Detection | 2 | T1583.005, T1071 |
| 12 | Watering Hole Attack | 2 | T1189, T1203 |
| 13 | SQL Injection Database | 1 | T1190, T1505 |
| 14 | Credential Stuffing | 1 | T1110.004, T1078 |
| 15 | USB Malware Propagation | 3 (Demo) | T1091, T1204 |
| 16 | Privilege Escalation | 2 | T1068, T1548 |
| 17 | DNS Tunnelling | 1 | T1071.004, T1048 |
| 18 | Drive-By Download | 2 | T1189, T1203 |
| 19 | Cryptojacking | 1 | T1496, T1071 |
| 20 | Ransomware Exploit Kit | 2 | T1189, T1486 |
| 21 | Domain Spoofing Vendor | 2 | T1583.001, T1036 |
| 22 | API Vulnerability Exploitation | 1 | T1190, T1059 |

### Tier Classification

- **Tier 1** - Fully implementable end-to-end with Python + Docker
- **Tier 2** - Substantially implementable with partial simulation
- **Tier 3** - Demo only (README + sample logs) due to hardware/service requirements

## Prerequisites

- **macOS** (Apple Silicon or Intel) or Linux
- **Docker Desktop** with at least 4GB RAM allocated
- **Python 3.10+**
- **~10GB** free disk space for Docker images

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/wcace-soc-scenarios.git
cd wcace-soc-scenarios

# 2. Install Python dependencies
pip3 install -r requirements.txt

# 3. Start the SOC stack
cd soc-stack
./scripts/setup.sh        # Pull images (first time only)
./scripts/start-core.sh   # Start core services

# 4. Access dashboards
# Wazuh Dashboard: https://localhost:5601 (admin/SecretPassword)
# Grafana: http://localhost:3000 (admin/admin)

# 5. Run a scenario (e.g., SQL Injection)
cd ../scenarios/13-sql-injection-database
python3 attack/simulate_attack.py
python3 detect/verify_detection.py
```

## On-Demand Services

Some scenarios require additional services launched via Docker Compose profiles:

```bash
# Incident Response (TheHive)
docker compose --profile ir up -d

# Vulnerable Web App (DVWA)
docker compose --profile webapp up -d

# Vulnerable API
docker compose --profile api up -d

# Phishing simulation
docker compose --profile phishing up -d

# DNS tunnelling
docker compose --profile dns up -d
```

## Project Structure

```
WCACE/
├── README.md                   # This file
├── requirements.txt            # Python dependencies
├── soc-stack/                  # Docker-based SOC infrastructure
│   ├── docker-compose.yml
│   └── scripts/
├── wcace_lib/                  # Shared Python library
│   ├── log_generator.py        # Syslog/JSON/CEF log generation
│   ├── siem_client.py          # Log forwarding to Wazuh/Loki
│   ├── network_sim.py          # Network traffic simulation
│   └── email_sim.py            # Email mock generation
└── scenarios/
    ├── 01-apt-deepfake-ceo/
    ├── ...
    └── 22-api-vulnerability-exploitation/
```

Each scenario directory contains:
- `README.md` - Description, MITRE ATT&CK mapping, execution guide
- `config/` - Suricata and Wazuh rules
- `attack/` - Attack simulation scripts
- `detect/` - Detection verification
- `respond/` - Containment scripts and IR playbook
- `logs/sample_logs/` - Pre-generated logs for offline demo

## License

This project is for educational purposes as part of the WCACE program at Western Sydney University.
