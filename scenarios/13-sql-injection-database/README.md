# Scenario 13: SQL Injection Database Attack

## Overview
Simulate a SQL injection attack against a vulnerable web application, demonstrating how attackers exploit improper input validation to extract, modify, or destroy database contents.

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Exploit Public-Facing Application | T1190 |
| Persistence | Server Software Component: Web Shell | T1505 |
| Collection | Data from Information Repositories | T1213 |
| Execution | Command and Scripting Interpreter | T1059 |

## Attack Flow

```
1. Reconnaissance     → Identify login form / search parameters
2. SQLi Probing       → Test for error-based / blind SQLi
3. Data Extraction    → UNION-based extraction of user table
4. Privilege Escal.   → Extract admin credentials from DB
5. Data Exfiltration  → Dump sensitive records
```

## Components

### Vulnerable Application (`attack/vuln_app.py`)
- Flask web app with intentionally vulnerable SQL queries
- SQLite database with sample user/financial data
- Endpoints: `/login`, `/search`, `/users`

### Attack Simulation (`attack/simulate_attack.py`)
- Automated SQLi payloads (error-based, UNION, blind)
- Progressive attack escalation
- Generates logs and alerts

### Detection Rules
- **Suricata**: `config/suricata-rules.rules` - HTTP payload inspection for SQL keywords
- **Wazuh**: `config/wazuh-rules.xml` - Web application attack correlation

### Verification (`detect/verify_detection.py`)
- Checks Suricata alerts for SQLi signatures
- Validates Wazuh alert generation
- Reports detection coverage

## How to Run

```bash
# 1. Start the vulnerable app
python3 attack/vuln_app.py &

# 2. Run the attack simulation
python3 attack/simulate_attack.py

# 3. Verify detection
python3 detect/verify_detection.py

# 4. Review response playbook
cat respond/playbook.md
```

## Prerequisites
- SOC stack running (`soc-stack/scripts/start-core.sh`)
- Or standalone mode (generates local log files)

## Sample Payloads
```sql
' OR 1=1--
' UNION SELECT NULL, username, password FROM users--
'; DROP TABLE users;--
' AND 1=CONVERT(int,(SELECT @@version))--
admin'--
```

## Expected Alerts
- Suricata SID 9000001-9000004: SQL Injection patterns
- Wazuh Rule 100100-100104: Web application SQLi correlation
