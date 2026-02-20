# Scenario 16: Privilege Escalation

## Overview
Simulate a privilege escalation attack chain on a Linux system: an attacker starts with normal user access, attempts unauthorized sudo usage, exploits a misconfigured SUID binary to gain root access, and creates a backdoor administrator account for persistence. Detection covers auth/sudo log monitoring, Wazuh rules for SUID abuse, and Suricata network signatures for suspicious privileged activity.

**Tier:** 2 (Full attack simulation with detection and response)

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Privilege Escalation | Exploitation for Privilege Escalation | T1068 |
| Privilege Escalation | Abuse Elevation Control Mechanism | T1548 |
| Persistence | Create Account: Local Account | T1136.001 |
| Defense Evasion | Abuse Elevation Control: Sudo | T1548.003 |

## Attack Flow

```
1. Normal User Access  -> Attacker logs in as regular user via SSH
2. Sudo Attempt        -> Attacker tries sudo without authorization (denied)
3. SUID Exploitation   -> Attacker finds and exploits misconfigured SUID binary
4. Root Access         -> Attacker gains root shell via SUID exploit
5. Backdoor Account    -> Attacker creates a hidden admin account for persistence
```

## Components

### Attack Simulation (`attack/simulate_attack.py`)
- **Phase 1:** Normal user SSH login -- generates auth log entries for legitimate access
- **Phase 2:** Unauthorized sudo attempts -- user not in sudoers, generates alert-level logs
- **Phase 3:** SUID binary discovery and exploitation -- finds misconfigured `/usr/bin/find` with SUID bit
- **Phase 4:** Root access -- exploits SUID binary to spawn root shell
- **Phase 5:** Backdoor creation -- creates hidden admin account `svc_support` with sudo privileges

All operations generate realistic syslog/auth log sequences via `LogGenerator`.

### Detection Rules
- **Suricata:** `config/suricata-rules.rules` -- Suspicious outbound connections from newly elevated process, abnormal SSH activity
- **Wazuh:** `config/wazuh-rules.xml` -- Unauthorized sudo attempt, SUID binary execution, root access from non-admin user, backdoor account creation (rule IDs 100540+)

### Verification (`detect/verify_detection.py`)
- Checks local logs for privilege escalation events
- Validates Wazuh alert generation for each attack phase
- Reports detection coverage

### Response
- **`respond/containment.py`** -- Kill attacker sessions, remove backdoor account, audit SUID binaries, block attacker IP
- **`respond/playbook.md`** -- Full incident response playbook for privilege escalation incidents

## How to Run

```bash
# 1. Install dependencies
pip install -r attack/requirements.txt

# 2. Run the full attack simulation
python3 attack/simulate_attack.py

# 3. Verify detection
python3 detect/verify_detection.py

# 4. Run containment response
python3 respond/containment.py

# 5. Review IR playbook
cat respond/playbook.md
```

## Prerequisites
- Python 3.10+
- SOC stack running (`soc-stack/scripts/start-core.sh`) or standalone mode (generates local log files)

## Safety Notes
- No actual privilege escalation is performed -- all activity is simulated via log generation
- No SUID binaries are modified or created
- No real user accounts are created or modified
- All logs are written to the sandbox `logs/sample_logs/` directory

## Expected Alerts
- Suricata SID 9160001-9160004: Privileged process network indicators
- Wazuh Rule 100540-100548: Sudo abuse, SUID exploitation, root access, backdoor account
