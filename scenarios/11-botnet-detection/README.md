# Scenario 11: Botnet Detection

## Overview
Simulate a botnet infection across multiple internal workstations. Multiple Python processes simulate C2 beaconing from different "infected" workstations, followed by DDoS traffic generation and a bot registration/tasking protocol. The scenario demonstrates how to detect coordinated botnet activity through network traffic analysis and behavioral correlation.

This scenario uses a simulated approach with partial implementation -- bot behavior is scripted to generate realistic multi-host C2 patterns.

## Tier
**Tier 2** -- Simulated with partial implementation

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Resource Development | Botnet | T1583.005 |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 |
| Impact | Network Denial of Service | T1498 |
| Execution | Command and Scripting Interpreter | T1059 |
| Discovery | System Information Discovery | T1082 |
| Lateral Movement | Exploitation of Remote Services | T1210 |

## Attack Flow

```
Phase 1: Bot Propagation          Phase 2: Bot Registration        Phase 3: C2 Beaconing
(Infection of workstations)       (Bots check in with C2)          (Coordinated callbacks)
  |                                 |                                 |
  v                                 v                                 v
Worm spreads to 8             -->  Each bot sends system info   -->  All bots beacon at
workstations via SMB               and gets unique bot_id            similar intervals
  |                                 |                                 |
  v                                 v                                 v
Phase 4: Tasking                  Phase 5: DDoS Attack             Phase 6: Data Theft
(C2 sends commands to bots)       (Coordinated flood attack)       (Credential harvesting)
  |                                 |                                 |
  v                                 v                                 v
Bots receive attack         -->  All bots flood target         -->  Bots collect and
commands simultaneously           with SYN/HTTP requests             exfiltrate creds
```

## Components

### Attack Simulation (`attack/simulate_attack.py`)
- Six-phase botnet lifecycle from propagation through coordinated attacks
- Simulates 8 infected workstations with concurrent C2 beaconing
- Generates DDoS traffic patterns and bot registration protocol logs

### Detection Rules
- **Suricata**: `config/suricata-rules.rules` -- Botnet C2 patterns, DDoS signatures
- **Wazuh**: `config/wazuh-rules.xml` -- Multi-host botnet correlation (rule IDs 100480-100489)

### Verification (`detect/verify_detection.py`)
- Analyzes logs for coordinated botnet behavior patterns
- Correlates activity across multiple infected hosts
- Reports detection coverage

### Response
- **Containment**: `respond/containment.py` -- Isolate infected segment, block C2, clean bots
- **Playbook**: `respond/playbook.md` -- Full IR playbook for botnet incident

## How to Run

```bash
# 1. Run the attack simulation (generates logs)
python3 attack/simulate_attack.py

# 2. Verify detection coverage
python3 detect/verify_detection.py

# 3. Execute containment response
python3 respond/containment.py

# 4. Review IR playbook
cat respond/playbook.md
```

## Prerequisites
- SOC stack running (`soc-stack/scripts/start-core.sh`)
- Or standalone mode (generates local log files in `logs/sample_logs/`)

## Expected Alerts
- Wazuh Rule 100480: Worm-like propagation -- SMB exploitation across workstations
- Wazuh Rule 100481: Bot registration with C2 server
- Wazuh Rule 100482: Coordinated C2 beaconing from multiple internal hosts
- Wazuh Rule 100483: Bot tasking command received from C2
- Wazuh Rule 100484: DDoS traffic generation from internal host
- Wazuh Rule 100485: Coordinated DDoS attack from botnet
- Wazuh Rule 100486: Credential harvesting by bot
- Wazuh Rule 100487: Data exfiltration by bot to C2
- Wazuh Rule 100488: Bot persistence mechanism installed
- Wazuh Rule 100489: Botnet campaign correlated -- multiple indicators
- Suricata SID 9110001-9110005: Botnet C2 and DDoS signatures
