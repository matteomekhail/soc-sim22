# Scenario 07: Zero-Day Exploit & Lateral Movement

## Overview
Simulate a zero-day exploit against an internal application that has no existing signature, followed by systematic lateral movement across multiple internal hosts via SSH and SMB. The attack generates log sequences showing sequential host compromise, demonstrating how a single zero-day can cascade into a full network breach.

This scenario uses a simulated approach with partial implementation -- the zero-day exploit and lateral movement are scripted to produce realistic log patterns.

## Tier
**Tier 2** -- Simulated with partial implementation

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Privilege Escalation | Exploitation for Privilege Escalation | T1068 |
| Lateral Movement | Remote Services: SSH | T1021.004 |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 |
| Execution | Command and Scripting Interpreter | T1059 |
| Discovery | Remote System Discovery | T1018 |
| Credential Access | OS Credential Dumping | T1003 |

## Attack Flow

```
Phase 1: Zero-Day Exploit          Phase 2: Internal Recon          Phase 3: Credential Harvest
(Unknown signature on API srv)     (Network discovery from beachhead) (Dump creds for pivoting)
  |                                  |                                 |
  v                                  v                                 v
Buffer overflow on API         -->  arp -a, nmap internal         -->  /etc/shadow, SSH keys,
server (10.0.1.20) via              subnet, service enum               mimikatz-style dump
crafted HTTP request
  |                                  |                                 |
  v                                  v                                 v
Phase 4: Lateral via SSH           Phase 5: Lateral via SMB         Phase 6: Domain Compromise
(SSH to workstations/servers)      (SMB to file server / DC)        (Access DC, extract AD data)
  |                                  |                                 |
  v                                  v                                 v
Sequential SSH to 5 hosts     -->  SMB access to file shares   -->  DC compromise, GPO access,
using harvested credentials        and admin shares                  full domain control
```

## Components

### Attack Simulation (`attack/simulate_attack.py`)
- Six-phase attack from zero-day through domain compromise
- Generates sequential host compromise patterns across multiple internal IPs
- Shows SSH and SMB-based lateral movement with realistic timing

### Detection Rules
- **Suricata**: `config/suricata-rules.rules` -- Zero-day anomaly, lateral movement patterns
- **Wazuh**: `config/wazuh-rules.xml` -- Sequential compromise correlation (rule IDs 100440-100449)

### Verification (`detect/verify_detection.py`)
- Analyzes generated logs for zero-day and lateral movement indicators
- Tracks sequential host compromise chain
- Reports detection coverage across all phases

### Response
- **Containment**: `respond/containment.py` -- Isolate compromised segment, block lateral paths
- **Playbook**: `respond/playbook.md` -- Full IR playbook for zero-day lateral movement

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
- Wazuh Rule 100440: Anomalous process crash on application server
- Wazuh Rule 100441: Zero-day exploit indicator -- unexpected shell spawn
- Wazuh Rule 100442: Internal network reconnaissance from compromised host
- Wazuh Rule 100443: Credential harvesting on compromised host
- Wazuh Rule 100444: Lateral movement via SSH -- sequential host access
- Wazuh Rule 100445: Lateral movement via SMB -- admin share access
- Wazuh Rule 100446: Sequential host compromise pattern detected
- Wazuh Rule 100447: Domain controller accessed from non-admin source
- Wazuh Rule 100448: Mass credential extraction from domain controller
- Wazuh Rule 100449: Zero-day lateral movement campaign correlated
- Suricata SID 9070001-9070005: Zero-day and lateral movement signatures
