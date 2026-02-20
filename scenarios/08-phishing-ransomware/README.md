# Scenario 08: Phishing & Ransomware

## Overview
Simulate a full ransomware attack chain: a phishing email carrying a malicious attachment is delivered to an employee, the attachment is opened and executes ransomware that encrypts files, and a ransom note is dropped. Detection covers email gateway alerts, Wazuh File Integrity Monitoring (FIM), and Suricata network signatures.

**Tier:** 1 (Full attack simulation with detection and response)

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 |
| Execution | User Execution: Malicious File | T1204.002 |
| Impact | Data Encrypted for Impact | T1486 |
| Command and Control | Application Layer Protocol | T1071 |

## Attack Flow

```
1. Phishing Email     -> Attacker sends email with malicious attachment
2. Attachment Opened  -> User opens attachment; payload drops to disk
3. C2 Beacon          -> Ransomware contacts C2 for encryption key
4. File Encryption    -> Files in sandbox dir encrypted with Fernet
5. Ransom Note        -> RANSOM_NOTE.txt created in each affected dir
6. FIM Alerts         -> Wazuh detects mass file modifications
```

## Components

### Attack Simulation (`attack/simulate_attack.py`)
- **Phase 1:** Generate phishing emails using `wcace_lib.email_sim.EmailSimulator`
- **Phase 2:** Simulate user opening attachment -- creates sandbox directory `/tmp/wcace-sandbox/victim-files/` with sample files
- **Phase 3:** Ransomware simulation -- encrypts files using `cryptography.fernet`, adds `.encrypted` extension, drops `RANSOM_NOTE.txt`
- **Phase 4:** Generate Wazuh FIM alerts (File Integrity Monitoring detects mass file changes)

All operations are sandboxed to `/tmp/wcace-sandbox/` with strict safety checks.

### Detection Rules
- **Suricata:** `config/suricata-rules.rules` -- Suspicious executable download, ransomware C2 communication
- **Wazuh:** `config/wazuh-rules.xml` -- FIM mass file modification, ransomware file extension detection, ransom note creation (rule IDs 100300+)

### Verification (`detect/verify_detection.py`)
- Checks local logs for phishing and encryption events
- Validates FIM alert generation
- Reports detection coverage

### Response
- **`respond/containment.py`** -- Isolate affected host, kill encryption process, preserve encryption key for recovery
- **`respond/playbook.md`** -- Full incident response playbook for ransomware incidents

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
- The `cryptography` package (`pip install cryptography`)

## Safety Notes
- All file encryption is restricted to `/tmp/wcace-sandbox/` only
- The script includes multiple safety checks to prevent operating outside the sandbox
- Encryption keys are logged for recovery during exercises
- No real malware is used -- encryption uses standard Fernet symmetric encryption

## Expected Alerts
- Suricata SID 9800001-9800004: Ransomware network indicators
- Wazuh Rule 100300-100306: FIM mass modification, ransomware extensions, ransom note
