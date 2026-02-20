# Incident Response Playbook: Dark Web Data Exposure

## Severity: HIGH
## MITRE ATT&CK: T1583, T1597

---

## 1. Detection
- [ ] Dark web monitoring tool alerts on company data
- [ ] HIBP API detects company emails in new breach
- [ ] Threat intelligence feed reports company mention
- [ ] Employee reports credential compromise notification

## 2. Triage
- [ ] Classify data type: credentials, PII, IP, financial
- [ ] Determine data freshness (current vs historical)
- [ ] Assess scope: how many records/accounts affected
- [ ] Verify if data matches current internal records

## 3. Containment
- [ ] Force password reset for all exposed accounts
- [ ] Revoke API keys and tokens found in dumps
- [ ] Enable enhanced monitoring on affected accounts
- [ ] Block known attacker infrastructure

## 4. Investigation
- [ ] Identify the source breach (internal vs third-party)
- [ ] Check if exposed credentials were used for unauthorized access
- [ ] Correlate with other security events
- [ ] Determine if the data is being actively sold/traded

## 5. Recovery
- [ ] Rotate all exposed credentials
- [ ] Notify affected individuals per regulation
- [ ] Update security controls based on exposure type
- [ ] File takedown requests for hosted data

## 6. Prevention
- Continuous dark web monitoring service
- Regular credential leak checks (HIBP, etc.)
- Employee security awareness training
- Data loss prevention (DLP) controls
- Third-party risk management program
