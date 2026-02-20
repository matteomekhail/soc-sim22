# Scenario 12: Watering Hole Attack

## Overview
Simulate a watering hole attack where an adversary compromises a legitimate industry website frequently visited by target employees. When employees browse the site, injected malicious JavaScript exploits a browser vulnerability (CVE-2024-4761) to deliver a payload that establishes C2 communication, sets up persistence, and performs post-exploitation reconnaissance including credential harvesting.

**Tier:** 2 (Multi-phase attack simulation with detection and response)

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Drive-by Compromise | T1189 |
| Execution | Exploitation for Client Execution | T1203 |
| Persistence | Registry Run Keys / Startup Folder | T1547.001 |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 |
| Discovery | System Information Discovery | T1082 |
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 |

## Attack Flow

```
                         ATTACKER (203.0.113.50)
                                |
                    [1] Compromise Website
                    (inject malicious JS)
                                |
                                v
                  +----------------------------+
                  | news-portal.test           |
                  | (industry news site)       |
                  | Injected: analytics-v3.js  |
                  +----------------------------+
                         |    |    |
            [2] Normal browsing by employees
                 /       |         \
                v        v          v
          +--------+ +--------+ +--------+
          | WS-100 | | WS-101 | | WS-102 |   <-- Employee workstations
          +--------+ +--------+ +--------+
               |          |          |
       [3] Browser exploit (CVE-2024-4761)
       (not all browsers vulnerable)
               |          |
               v          v
          +--------+ +--------+
          | WS-100 | | WS-101 |   <-- Exploited hosts
          +--------+ +--------+
               |          |
    [4] Payload execution + persistence
    (msedge_update.exe + registry run key)
               |          |
               v          v
         +--------------------------+
         | C2 SERVER (203.0.113.100)|
         +--------------------------+
               |          |
    [5] Post-exploitation:
    - C2 beaconing
    - System discovery (systeminfo, whoami, net user)
    - Credential harvesting (LSASS dump)
    - Data exfiltration over C2
```

## Components

### Attack Simulation (`attack/simulate_attack.py`)
- **Phase 1:** Website Compromise -- Attacker probes and injects malicious JavaScript into a popular industry news website
- **Phase 2:** Victim Browsing -- Multiple employees visit the compromised site during normal work hours, loading the injected script
- **Phase 3:** Browser Exploitation -- Malicious JavaScript exploits CVE-2024-4761 (Chrome V8 type confusion) to download a payload via drive-by
- **Phase 4:** Payload Execution -- Dropped malware (`msedge_update.exe`) establishes C2 via TLS and sets persistence via registry run key
- **Phase 5:** Post-Exploitation -- C2 beaconing, system reconnaissance commands, LSASS credential dump, and data exfiltration over the C2 channel

All activity is simulated via log generation only. No real exploitation occurs.

### Detection Rules
- **Suricata:** `config/suricata-rules.rules` -- Website modification, exploit kit delivery, C2 beacon, recon activity, data exfiltration (SIDs 9120001-9120005)
- **Wazuh:** `config/wazuh-rules.xml` -- Website compromise, employee visits, browser exploit, drive-by download, persistence, C2, recon, credential harvesting, exfiltration, kill chain correlation (Rule IDs 100500-100509)

### Verification (`detect/verify_detection.py`)
- Checks local logs for all five attack phases
- Validates exploit indicators (CVE, C2, persistence, credential harvesting)
- Verifies phase log completeness
- Optionally queries Wazuh and Loki for live alerts

### Response
- **`respond/containment.py`** -- Block compromised website, isolate infected hosts, block C2, remove persistence, scan all visitor endpoints, preserve evidence
- **`respond/playbook.md`** -- Comprehensive incident response playbook for watering hole attacks

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
- `colorama` and `requests` packages (`pip install -r attack/requirements.txt`)

## Expected Alerts

### Suricata IDS Rules
| SID | Description | Phase |
|-----|-------------|-------|
| 9120001 | Suspicious web application modification from external IP | Website Compromise |
| 9120002 | Browser exploit kit delivery detected (drive-by download) | Browser Exploitation |
| 9120003 | Watering hole payload C2 beacon detected | C2 Communication |
| 9120004 | Post-exploitation reconnaissance from compromised host | Post-Exploitation |
| 9120005 | Suspicious data exfiltration to C2 - large TLS upload | Data Exfiltration |

### Wazuh SIEM Rules
| Rule ID | Level | Description | Phase |
|---------|-------|-------------|-------|
| 100500 | 10 | Suspicious web application modification detected | Website Compromise |
| 100501 | 8 | Multiple employees visiting suspected watering hole site | Victim Browsing |
| 100502 | 14 | Browser exploitation attempt detected | Browser Exploitation |
| 100503 | 12 | Suspicious file downloaded via drive-by | Browser Exploitation |
| 100504 | 12 | Registry run key persistence added | Persistence |
| 100505 | 13 | C2 communication from compromised host | C2 Communication |
| 100506 | 10 | System reconnaissance commands executed | Post-Exploitation |
| 100507 | 14 | Credential harvesting - LSASS memory dump | Post-Exploitation |
| 100508 | 13 | Data exfiltration to C2 server | Data Exfiltration |
| 100509 | 15 | Watering hole attack kill chain (correlation) | Kill Chain |

## Key IOCs
| Type | Value | Description |
|------|-------|-------------|
| IP | 203.0.113.50 | Attacker IP |
| IP | 203.0.113.100 | C2 server |
| IP | 198.51.100.25 | Compromised website IP |
| Domain | news-portal.test | Compromised watering hole website |
| Domain | updates.evil-cdn.test | C2 domain |
| URL | /assets/js/analytics-v3.min.js | Injected malicious JavaScript |
| File | msedge_update.exe | Malware payload |
| Registry | HKCU\..\Run\EdgeUpdate | Persistence mechanism |
| CVE | CVE-2024-4761 | Exploited Chrome V8 vulnerability |
