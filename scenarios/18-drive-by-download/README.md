# Scenario 18: Drive-By Download

## Overview
Simulate a drive-by download attack chain: a compromised advertisement network serves malicious ads on a legitimate website, an exploit kit probes the user's browser for vulnerabilities, a malicious download is triggered without user interaction, and the payload executes on the victim workstation. Detection covers web proxy logs, Wazuh rules for exploit kit activity, and Suricata network signatures for malicious downloads.

**Tier:** 2 (Full attack simulation with detection and response)

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Drive-By Compromise | T1189 |
| Execution | Exploitation for Client Execution | T1203 |
| Execution | User Execution: Malicious File | T1204.002 |
| Command and Control | Application Layer Protocol: Web | T1071.001 |

## Attack Flow

```
1. Compromised Ad Network  -> Malicious ad injected into ad rotation
2. Legitimate Site Visit   -> User visits news site with compromised ad iframe
3. Browser Probing         -> Exploit kit fingerprints browser/plugins
4. Malicious Download      -> Drive-by download triggered via exploit
5. Payload Execution       -> Downloaded payload executes on victim
```

## Components

### Attack Simulation (`attack/simulate_attack.py`)
- **Phase 1:** Compromised ad network injects malicious JavaScript/iframe
- **Phase 2:** User browses legitimate site; ad loads hidden iframe pointing to exploit kit
- **Phase 3:** Exploit kit probes browser version, Java, Flash, PDF plugins
- **Phase 4:** Malicious download triggered via browser exploit (no user click)
- **Phase 5:** Payload execution simulated -- beacon to C2

All operations generate realistic web access/proxy log sequences via `LogGenerator`.

### Detection Rules
- **Suricata:** `config/suricata-rules.rules` -- Exploit kit landing page, malicious iframe, suspicious download
- **Wazuh:** `config/wazuh-rules.xml` -- Exploit kit probing, drive-by download, payload execution (rule IDs 100560+)

### Verification (`detect/verify_detection.py`)
- Checks local logs for drive-by download events
- Validates Wazuh alert generation for each attack phase
- Reports detection coverage

### Response
- **`respond/containment.py`** -- Block malicious domains, quarantine downloaded files, isolate victim host
- **`respond/playbook.md`** -- Full incident response playbook for drive-by download incidents

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
- No actual exploit kits or malware are used
- No real downloads or browser exploitation occurs
- All activity is simulated through log generation
- Sample HTML content is for demonstration purposes only

## Expected Alerts
- Suricata SID 9180001-9180006: Exploit kit and malicious download indicators
- Wazuh Rule 100560-100568: Ad compromise, exploit kit probing, drive-by download, payload execution
