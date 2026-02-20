# Scenario 10: APT with Remote Access Trojan

## Overview
Simulate an APT campaign that deploys a Remote Access Trojan (RAT) on a compromised workstation. The RAT establishes a Python reverse shell to localhost (simulating C2 connectivity), implements C2 beaconing patterns with regular-interval HTTP callbacks, and executes remote commands to exfiltrate data.

This scenario uses a simulated approach with partial implementation -- the RAT behavior is scripted to generate realistic C2 communication patterns and command execution logs.

## Tier
**Tier 2** -- Simulated with partial implementation

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Command and Control | Remote Access Software | T1219 |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 |
| Execution | Command and Scripting Interpreter: Python | T1059.006 |
| Persistence | Scheduled Task/Job: Cron | T1053.003 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 |
| Defense Evasion | Obfuscated Files or Information | T1027 |

## Attack Flow

```
Phase 1: RAT Delivery           Phase 2: RAT Installation        Phase 3: C2 Beaconing
(Phishing -> trojanized doc)    (Persistence + evasion)           (Regular HTTP callbacks)
  |                               |                                 |
  v                               v                                 v
Email attachment drops      -->  Python RAT installed in       -->  HTTP POST to C2 every
Python RAT payload               %APPDATA% with cron persist       60s with system info
  |                               |                                 |
  v                               v                                 v
Phase 4: Command Execution      Phase 5: Data Collection         Phase 6: Exfiltration
(Remote commands via C2)        (Keylogging + screenshots)       (Data upload over C2)
  |                               |                                 |
  v                                v                                 v
System enumeration,         -->  Collect sensitive files,    -->  Compress and upload via
credential access                screenshots, keylog data         C2 HTTP channel
```

## Components

### Attack Simulation (`attack/simulate_attack.py`)
- Six-phase RAT lifecycle from delivery through exfiltration
- Generates realistic C2 beaconing patterns with regular intervals
- Simulates command execution and data collection activities

### Detection Rules
- **Suricata**: `config/suricata-rules.rules` -- C2 beaconing, RAT communication patterns
- **Wazuh**: `config/wazuh-rules.xml` -- RAT detection and C2 correlation (rule IDs 100460-100469)

### Verification (`detect/verify_detection.py`)
- Analyzes generated logs for RAT and C2 beaconing indicators
- Checks beacon interval regularity, command execution patterns
- Reports detection coverage

### Response
- **Containment**: `respond/containment.py` -- Kill RAT process, block C2, clean persistence
- **Playbook**: `respond/playbook.md` -- Full IR playbook for RAT incident

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

## Key Detection Concept
C2 beaconing detection relies on identifying **regular-interval callbacks** to the same external host. The RAT beacons every ~60 seconds with slight jitter. Statistical analysis of connection intervals reveals the periodic pattern that distinguishes C2 from legitimate traffic.

## Expected Alerts
- Wazuh Rule 100460: Suspicious Python process spawned from document handler
- Wazuh Rule 100461: RAT installation with persistence mechanism
- Wazuh Rule 100462: C2 beaconing pattern detected -- regular interval callbacks
- Wazuh Rule 100463: RAT command execution via C2 channel
- Wazuh Rule 100464: Credential access via RAT
- Wazuh Rule 100465: Data staging for exfiltration via RAT
- Wazuh Rule 100466: Data exfiltration over C2 channel
- Wazuh Rule 100467: Keylogger or screen capture activity
- Wazuh Rule 100468: RAT cleanup/anti-forensics activity
- Wazuh Rule 100469: APT RAT campaign correlated -- multiple indicators
- Suricata SID 9100001-9100005: C2 beaconing and RAT signatures
