# Scenario 21: Domain Spoofing Vendor

## Overview

An attacker registers a domain that closely resembles a legitimate vendor/supplier
used by the company. Using this spoofed domain, the attacker sends fraudulent
invoices and payment-redirect emails impersonating the vendor, attempting to divert
business payments to attacker-controlled bank accounts.

This is a Business Email Compromise (BEC) variant focused on vendor impersonation
and payment fraud rather than credential theft.

## MITRE ATT&CK Mapping

| Tactic                | Technique ID | Technique Name                       |
|-----------------------|-------------|--------------------------------------|
| Resource Development  | T1583.001   | Acquire Infrastructure: Domains      |
| Defense Evasion       | T1036       | Masquerading                         |
| Initial Access        | T1566.002   | Phishing: Spearphishing Link         |
| Impact                | T1565       | Data Manipulation (payment redirect) |

## Tier

**Tier 2** -- DNS spoofing + cloned website pattern (shared with Scenario 02).

## Attack Flow

```
Phase 1: Vendor Domain Registration
  Attacker identifies vendor used by AcmeCorp: globalparts-supply.test
  Registers lookalike: g1obalparts-supply.test (1 vs l)

Phase 2: Fake Invoice Campaign
  Sends emails from accounts@g1obalparts-supply.test
  Impersonates vendor account manager
  Attaches fake invoices with updated bank details

Phase 3: Payment Redirect
  Finance team processes the fake invoice
  Wires payment to attacker-controlled bank account
  Attacker launders the funds
```

## Directory Structure

```
21-domain-spoofing-vendor/
  attack/
    simulate_attack.py            # Full attack simulation script
    requirements.txt              # Python dependencies
  config/
    suricata-rules.rules          # Suricata rules for vendor domain spoofing
    wazuh-rules.xml               # Wazuh rules (100700+) for vendor fraud indicators
  detect/
    expected_alerts.json           # Expected alert definitions
    verify_detection.py            # Verify detection coverage
  logs/
    sample_logs/                   # Generated logs (output from simulate_attack.py)
  respond/
    containment.py                 # Block spoofed domain, alert finance, freeze payments
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

- **DNS Monitoring**: Detect DNS queries to vendor-lookalike domains
- **Email Filtering**: Flag emails from domains visually similar to known vendor domains
- **SPF/DKIM/DMARC Enforcement**: Reject emails failing authentication from vendor-like domains
- **Invoice Anomaly Detection**: Alert on bank detail changes in invoices
- **Vendor Communication Verification**: Out-of-band verification for payment changes
- **Domain Age Analysis**: Flag emails from newly registered domains
