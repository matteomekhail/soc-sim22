# Scenario 9: Insider Data Theft via Encrypted Exfiltration

## Overview
A malicious insider with legitimate database access exploits their privileges to systematically extract sensitive data, encrypt it, and exfiltrate it through covert channels to avoid detection.

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Collection | Data from Cloud Storage | T1530 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 |
| Defense Evasion | Obfuscated Files or Information | T1027 |
| Credential Access | Valid Accounts | T1078 |

## Attack Flow

```
1. Legitimate Access   → Use valid DB credentials during normal hours
2. Query Escalation    → Gradually increase query scope over days
3. Data Staging        → Export query results to local staging area
4. Encryption          → Encrypt staged data with AES-256
5. Covert Exfil        → Transfer via DNS/HTTPS in small chunks
```

## Difference from Scenario 4
- Scenario 4: File-level exfiltration (bulk file copy)
- Scenario 9: Database-level theft (SQL queries, encrypted exports, covert channels)

## Components

### Attack Simulation (`attack/simulate_attack.py`)
- Simulates DB access patterns escalating over time
- Generates encrypted data exports
- Exfiltrates via HTTPS in chunks disguised as normal API calls

### Detection
- Database audit log anomalies
- Encrypted file creation in unusual locations
- Outbound transfer pattern analysis

## How to Run

```bash
python3 attack/simulate_attack.py
python3 detect/verify_detection.py
```

## Expected Alerts
- Wazuh: Unusual database query volume
- Wazuh: Encrypted file created in staging directory
- Suricata: Chunked HTTPS exfiltration pattern
