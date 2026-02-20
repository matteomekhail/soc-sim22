# Incident Response Playbook: Financial Transaction Fraud

## Severity: CRITICAL
## MITRE ATT&CK: T1657, T1565

---

## 1. Detection
- [ ] Transaction monitoring system flags anomalous patterns
- [ ] Reconciliation discrepancies discovered
- [ ] Customer/vendor reports incorrect payment
- [ ] Audit log integrity check fails

## 2. Immediate Actions
- [ ] Freeze all pending transactions from compromised accounts
- [ ] Contact receiving banks to freeze fraudulent transfers
- [ ] Isolate compromised workstations
- [ ] Preserve all transaction and audit logs

## 3. Containment
- [ ] Reset all finance team credentials
- [ ] Enable enhanced MFA on transaction systems
- [ ] Implement manual approval for all transactions temporarily
- [ ] Block compromised IP addresses

## 4. Investigation
- [ ] Identify all altered/fraudulent transactions
- [ ] Determine initial access vector
- [ ] Audit all transactions from the compromise period
- [ ] Check for persistent access mechanisms

## 5. Recovery
- [ ] Reverse fraudulent transactions where possible
- [ ] Restore transaction records from verified backups
- [ ] Implement transaction integrity monitoring
- [ ] Resume normal operations with enhanced controls

## 6. Prevention
- Dual authorization for all financial transactions
- Real-time transaction anomaly detection
- Segregation of duties enforcement
- Regular reconciliation audits
- Behavioral analytics for finance users
