# Scenario 14: Credential Stuffing Attack

## Overview
Simulate a credential stuffing attack against a web application login endpoint, demonstrating how attackers use leaked username/password combinations to gain unauthorized access to accounts. Unlike brute force, credential stuffing relies on previously compromised credentials from data breaches, testing them across multiple services.

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Credential Access | Brute Force: Credential Stuffing | T1110.004 |
| Initial Access | Valid Accounts | T1078 |

## Attack Flow

```
1. Wordlist Preparation  -> Gather leaked usernames and common passwords
2. Target Reconnaissance -> Identify login endpoint and form parameters
3. Credential Stuffing   -> Automated login attempts with username/password combos
4. Account Compromise    -> Successful login with valid credentials
5. Lateral Movement      -> Use compromised accounts for further access
```

## Components

### Vulnerable Application (`attack/vuln_app.py`)
- Flask web app with rate limiting intentionally disabled
- SQLite database with sample user accounts
- Endpoints: `/login`, `/status`, `/users`
- No account lockout mechanism

### Attack Simulation (`attack/simulate_attack.py`)
- Credential stuffing attack using wordlists
- Tests multiple usernames with common passwords
- Generates realistic attack logs and IDS alerts
- Outputs results with colorama formatting

### Wordlists (`attack/wordlists/`)
- `common_passwords.txt` - Top 50 commonly used passwords
- `common_usernames.txt` - 20 common usernames

### Detection Rules
- **Suricata**: `config/suricata-rules.rules` - HTTP POST flood detection for `/login` endpoint
- **Wazuh**: `config/wazuh-rules.xml` - Multiple authentication failures from same IP correlation

### Verification (`detect/verify_detection.py`)
- Checks local logs for credential stuffing indicators
- Validates Wazuh alert generation
- Queries Loki for attack logs
- Reports detection coverage

### Response
- **Containment**: `respond/containment.py` - Block IP, enable rate limiting, account lockout
- **Playbook**: `respond/playbook.md` - Full IR procedure for credential stuffing incidents

## How to Run

```bash
# 1. Start the vulnerable app
python3 attack/vuln_app.py &

# 2. Run the attack simulation
python3 attack/simulate_attack.py

# 3. Verify detection
python3 detect/verify_detection.py

# 4. Run containment response
python3 respond/containment.py

# 5. Review response playbook
cat respond/playbook.md
```

## Prerequisites
- SOC stack running (`soc-stack/scripts/start-core.sh`)
- Or standalone mode (generates local log files)

## Expected Alerts
- Suricata SID 9200001-9200003: Login flood and credential stuffing patterns
- Wazuh Rule 100200-100204: Authentication failure correlation from same source IP
