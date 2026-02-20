# Scenario 02: Domain Spoofing & Data Theft

## Overview

An attacker registers a lookalike domain that closely resembles the company's
legitimate domain, clones the corporate login page, and deploys it on a phishing
server. Phishing emails lure employees to the fake site, where their credentials
are harvested. The attacker then uses those stolen credentials to access internal
systems and exfiltrate sensitive data.

## MITRE ATT&CK Mapping

| Tactic                | Technique ID | Technique Name                       |
|-----------------------|-------------|--------------------------------------|
| Resource Development  | T1583.001   | Acquire Infrastructure: Domains      |
| Command and Control   | T1071       | Application Layer Protocol           |
| Credential Access     | T1078       | Valid Accounts (stolen credentials)  |
| Initial Access        | T1566.002   | Phishing: Spearphishing Link         |
| Exfiltration          | T1041       | Exfiltration Over C2 Channel         |

## Tier

**Tier 2** -- DNS spoofing + cloned website pattern.

## Attack Flow

```
Phase 1: Domain Registration
  Attacker registers acmec0rp.local (lookalike of acmecorp.local)

Phase 2: Phishing Infrastructure
  Deploy cloned corporate login page on acmecorp-login.test
  Configure phishing-nginx container to serve the cloned site

Phase 3: Phishing Campaign
  Send phishing emails with links to the fake login page
  Emails impersonate IT Security with "Password Reset Required" subject

Phase 4: Credential Harvesting
  Victims enter credentials on the fake site
  credential-harvester.js captures form data and POSTs to attacker endpoint

Phase 5: Data Exfiltration
  Attacker logs in with stolen credentials
  Accesses sensitive files on internal servers
  Exfiltrates data over HTTPS to attacker-controlled server
```

## Directory Structure

```
02-domain-spoofing-data-theft/
  attack/
    phishing-site/
      index.html                  # Cloned AcmeCorp login page
      credential-harvester.js     # JS that captures form submissions
    simulate_attack.py            # Full attack simulation script
    requirements.txt              # Python dependencies
  config/
    suricata-rules.rules          # Suricata rules for spoofed domain detection
    wazuh-rules.xml               # Wazuh rules (100200+) for phishing indicators
  detect/
    expected_alerts.json           # Expected alert definitions
    verify_detection.py            # Verify detection coverage
  logs/
    sample_logs/                   # Generated logs (output from simulate_attack.py)
  respond/
    containment.py                 # DNS sinkhole, block domain, reset credentials
    playbook.md                    # Incident response playbook
```

## How to Run

### 1. Simulate the Attack

```bash
cd attack/
pip install -r requirements.txt
python simulate_attack.py
```

This generates sample logs in `logs/sample_logs/`.

### 2. Verify Detection

```bash
cd detect/
python verify_detection.py
```

### 3. Execute Containment

```bash
cd respond/
python containment.py --mode simulate
```

## Detection Strategy

- **DNS Monitoring**: Detect DNS queries to known-bad or lookalike domains
- **Email Filtering**: Flag emails with SPF/DKIM/DMARC failures from lookalike domains
- **Web Proxy Logs**: Identify connections to newly registered or suspicious domains
- **Credential Monitoring**: Alert on logins from unusual IP addresses or locations
- **Suricata IDS**: Signature-based detection of phishing domain access
- **Wazuh HIDS**: Rule-based alerting on credential theft and data exfiltration patterns
