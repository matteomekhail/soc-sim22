# Scenario 3: Financial Transaction Fraud

## Tier: 3 (Demo Only)

## Overview
Attackers compromise financial transaction systems to manipulate or create fraudulent transactions, alter payment amounts, or redirect funds to attacker-controlled accounts.

## Why Demo Only
- Requires realistic financial transaction processing system
- Banking API simulation needs complex state management
- Regulatory compliance testing infrastructure not available
- Transaction monitoring systems are proprietary

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Impact | Financial Theft | T1657 |
| Impact | Data Manipulation | T1565 |
| Persistence | Valid Accounts | T1078 |
| Collection | Data from Information Repositories | T1213 |

## Attack Flow

```
1. Account Compromise  → Phish finance team credentials
2. System Access       → Log into transaction management system
3. Reconnaissance      → Study transaction patterns and limits
4. Manipulation        → Alter pending transaction details
5. Fund Redirection    → Change recipient account numbers
6. Cover Tracks        → Modify audit logs, delete alerts
```

## Detection Indicators

### Transaction Anomalies
- Transaction amount modified after initial creation
- Recipient account changed on pending transactions
- Transactions just below authorization thresholds
- Unusual transaction volume outside business hours
- New beneficiary accounts in high-risk jurisdictions

### Access Anomalies
- Login from unusual location/IP for finance users
- Access to transaction system outside normal hours
- Multiple failed login attempts followed by success
- Concurrent sessions from different locations

### Audit Trail
- Gaps in audit log sequence numbers
- Log entries modified or deleted
- Timestamp inconsistencies in transaction records

## Sample Logs
Pre-generated logs in `logs/sample_logs/` demonstrate the attack lifecycle.

## SOC Response
See `respond/playbook.md` for incident response procedures.

## Tools for Further Study
- **OWASP Testing Guide**: Financial application security testing
- **SWIFT CSP**: Customer Security Programme for banking
- **PCI DSS**: Payment Card Industry standards
