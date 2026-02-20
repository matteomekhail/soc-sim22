# Scenario 04: Insider Threat Data Exfiltration

## Overview
Simulate a malicious insider who gradually escalates from normal file access patterns to bulk data collection and exfiltration. This scenario focuses on **behavioral detection** -- identifying anomalies from an established baseline rather than relying on signatures.

The insider (a trusted employee) leverages legitimate credentials and authorized access to stage and exfiltrate sensitive data from HR, Finance, and Executive file shares via HTTPS transfers to an external destination.

## Tier
**Tier 1** -- Core detection scenario

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Exfiltration | Exfiltration Over Web Service | T1567 |
| Exfiltration | Exfiltration Over Alternative Protocol | T1048 |
| Collection | Data Staged: Local Data Staging | T1074.001 |
| Collection | Data from Network Shared Drive | T1039 |
| Defense Evasion | Valid Accounts: Domain Accounts | T1078.002 |

## Attack Flow

```
Phase 1: Normal Access          Phase 2: After-Hours Access       Phase 3: Bulk Download
(Baseline Behavior)             (Anomalous Timing)                (Volume Anomaly)
  |                               |                                 |
  v                               v                                 v
Working-hours file access  -->  22:00-03:00 access to       -->  50+ files accessed
to project directories          HR/, Finance/, Executive/         in < 30 minutes
  |                               |                                 |
  v                               v                                 v
Phase 4: Data Staging           Phase 5: Exfiltration
(Compression Activity)         (Large Outbound Transfers)
  |                               |
  v                               v
tar/zip of collected      -->  Multiple large HTTPS uploads
files in /tmp                   to external IP (203.0.113.50)
```

## Components

### Attack Simulation (`attack/simulate_attack.py`)
- Five-phase insider threat progression
- Generates contrasting normal vs. anomalous log patterns
- Produces file access, authentication, firewall, and data transfer logs

### Detection Rules
- **Suricata**: `config/suricata-rules.rules` -- Large outbound data transfer detection
- **Wazuh**: `config/wazuh-rules.xml` -- Behavioral rules for after-hours access, bulk file operations, and volumetric anomalies (rule IDs 100400-100406)

### Verification (`detect/verify_detection.py`)
- Analyzes generated logs for insider threat behavioral indicators
- Checks after-hours access, volume anomalies, staging activity, and exfiltration patterns
- Reports detection coverage

### Response
- **Containment**: `respond/containment.py` -- Disable account, revoke VPN, preserve evidence
- **Playbook**: `respond/playbook.md` -- Full IR playbook for insider threat incidents

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

This scenario demonstrates **behavioral anomaly detection** vs. signature-based detection:

| Aspect | Signature-Based | Behavioral (This Scenario) |
|--------|----------------|---------------------------|
| Approach | Match known-bad patterns | Deviation from baseline |
| Example | Block known malware hash | User accessing 50 files vs. usual 5 |
| Strength | Low false positives | Catches novel/insider threats |
| Weakness | Misses zero-day/insiders | Requires baseline tuning |

## Expected Alerts
- Wazuh Rule 100400: After-hours sensitive file access
- Wazuh Rule 100401: Bulk file access exceeding baseline
- Wazuh Rule 100402: Data staging (compression) activity
- Wazuh Rule 100403: Large outbound HTTPS data transfer
- Wazuh Rule 100404: Anomalous access to multiple sensitive directories
- Wazuh Rule 100405: Multiple insider threat indicators correlated
- Wazuh Rule 100406: Data exfiltration to external IP
- Suricata SID 9040001-9040004: Large/anomalous outbound transfers
