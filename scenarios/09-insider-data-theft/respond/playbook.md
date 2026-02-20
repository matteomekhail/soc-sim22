# Incident Response Playbook: Insider Data Theft

## Scenario 9 - Database Exfiltration via Encrypted Channels

### Severity: CRITICAL
### MITRE ATT&CK: T1530 (Data from Cloud Storage), T1041 (Exfiltration Over C2)

---

## 1. Detection
- [ ] Database audit logs show unusual query patterns
- [ ] Large data exports from sensitive tables
- [ ] Encrypted files created in temporary/hidden directories
- [ ] Abnormal outbound HTTPS traffic volume
- [ ] DNS tunnelling activity detected

## 2. Triage (First 15 minutes)
- [ ] Identify the user account performing suspicious queries
- [ ] Correlate DB access with normal job responsibilities
- [ ] Determine scope of data accessed (tables, row counts)
- [ ] Check if data has already left the network
- [ ] Assess data classification level (PII, financial, credentials)

## 3. Containment (First 30 minutes)
- [ ] **DO NOT alert the insider** (preserve investigation integrity)
- [ ] Disable outbound connectivity for the workstation
- [ ] Revoke database access for the account
- [ ] Enable enhanced monitoring on all the user's accounts
- [ ] Snapshot the workstation disk for forensics
- [ ] Preserve network logs and database audit trails

## 4. Eradication
- [ ] Revoke all access credentials for the insider
- [ ] Disable VPN, email, and remote access
- [ ] Review and revoke any API keys or service accounts
- [ ] Check for data copies on cloud services (personal drives)
- [ ] Audit all queries run by the user in the past 90 days

## 5. Recovery
- [ ] Assess what data was compromised
- [ ] Notify affected parties per data breach regulations
- [ ] Rotate credentials for any exposed accounts
- [ ] Implement database query monitoring and alerting
- [ ] Review and restrict database access based on least privilege

## 6. Legal & HR
- [ ] Engage legal counsel
- [ ] Coordinate with HR for employee action
- [ ] Preserve evidence chain of custody
- [ ] File regulatory notifications if PII was breached
- [ ] Consider law enforcement referral

## 7. Prevention
- Implement database activity monitoring (DAM)
- DLP policies for sensitive data exports
- Network segmentation for database servers
- Regular access reviews for sensitive data
- Behavioral analytics for insider threat detection
