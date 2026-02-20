# Scenario 19: Cryptojacking

## Overview
Simulate a cryptojacking attack where a compromised website serves JavaScript-based cryptocurrency mining code to visitors. The injected miner runs in the victim's browser, consuming CPU resources while connecting to a mining pool to submit proof-of-work hashes.

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Impact | Resource Hijacking | T1496 |
| Command and Control | Application Layer Protocol | T1071 |
| Initial Access | Drive-by Compromise | T1189 |
| Execution | User Execution | T1204 |

## Attack Flow

```
1. Website Compromise  → Attacker injects coinhive-style JS into legitimate website
2. Victim Browses      → User visits compromised site, mining JS loads in browser
3. Mining Execution    → Browser JS begins crypto mining (high CPU usage)
4. Pool Connection     → Miner connects to pool.cryptomine.test via HTTP/stratum
5. Sustained Mining    → Periodic check-ins with mining pool (beacon pattern)
```

## Components

### Vulnerable Website (`attack/vuln_website.py`)
- Flask web app serving a page with embedded JavaScript crypto miner simulation
- Injected coinhive-style JS snippet (simulated, no actual mining)
- Demonstrates how legitimate websites are weaponized

### Attack Simulation (`attack/simulate_attack.py`)
- Phase 1: User visits compromised website
- Phase 2: Mining JS loaded and "executed" in browser
- Phase 3: Simulated connections to mining pool (HTTP/stratum to pool.cryptomine.test)
- Phase 4: Sustained beacon pattern (mining pool check-ins)
- Generates logs to `logs/sample_logs/`

### Detection Rules
- **Suricata**: `config/suricata-rules.rules` - Mining pool connections, coinhive JS, stratum protocol
- **Wazuh**: `config/wazuh-rules.xml` - Cryptojacking detection correlation (rule IDs 100600+)

### Verification (`detect/verify_detection.py`)
- Checks local logs for mining indicators
- Validates Wazuh and Loki alert generation
- Reports detection coverage

### Response
- **Containment** (`respond/containment.py`): Block mining pool, remove injected JS, scan for persistence
- **Playbook** (`respond/playbook.md`): Full IR procedure for cryptojacking incidents

## How to Run

```bash
# 1. Start the compromised website (optional - for live demo)
python3 attack/vuln_website.py &

# 2. Run the attack simulation
python3 attack/simulate_attack.py

# 3. Verify detection
python3 detect/verify_detection.py

# 4. Execute containment response
python3 respond/containment.py

# 5. Review response playbook
cat respond/playbook.md
```

## Prerequisites
- SOC stack running (`soc-stack/scripts/start-core.sh`)
- Or standalone mode (generates local log files)

## Expected Alerts
- Suricata SID 9190001-9190005: Mining pool connections, coinhive JS, stratum protocol
- Wazuh Rule 100600-100605: Cryptojacking detection and correlation
