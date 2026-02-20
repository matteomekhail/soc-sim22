# Incident Response Playbook: Credential Stuffing Attack

## Scenario 14 - Credential Stuffing

### Severity: HIGH
### MITRE ATT&CK: T1110.004 (Credential Stuffing), T1078 (Valid Accounts)

---

## 1. Detection
- [ ] Suricata alert: High-frequency POST requests to `/login` endpoint
- [ ] Wazuh alert: Multiple authentication failures from same source IP (rule 100201)
- [ ] Wazuh alert: Credential stuffing confirmed - high volume failures (rule 100202)
- [ ] Wazuh alert: Account compromise after credential stuffing (rule 100203)
- [ ] Application logs show spike in failed login attempts
- [ ] Anomalous login patterns (e.g., many different usernames from single IP)

## 2. Triage (First 15 minutes)
- [ ] Confirm the alert is a true positive (not a legitimate user or automated test)
- [ ] Identify all source IP addresses involved in the attack
- [ ] Determine if the attack is from a single IP or distributed across multiple IPs
- [ ] Check if any accounts were successfully compromised
- [ ] Check threat intelligence feeds for known credential dump sources
- [ ] Assess if compromised credentials match any recent public data breaches

## 3. Containment (First 30 minutes)
- [ ] **Immediate**: Block attacker IP(s) at WAF/firewall level
- [ ] **Immediate**: Enable rate limiting on login endpoint
- [ ] **Immediate**: Lock any compromised accounts
- [ ] Force password reset for compromised accounts
- [ ] Enable CAPTCHA on login form
- [ ] Notify affected users of potential account compromise

### Containment Commands
```bash
# Block attacker IP (iptables)
iptables -A INPUT -s <ATTACKER_IP> -j DROP

# Block subnet if distributed attack
iptables -A INPUT -s <ATTACKER_SUBNET>/24 -j DROP

# Enable nginx rate limiting (add to config)
# limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;

# Check for active sessions from attacker IP
netstat -an | grep <ATTACKER_IP>

# Run containment script
python3 respond/containment.py
```

## 4. Eradication
- [ ] Revoke all sessions for compromised accounts
- [ ] Force password change for all compromised accounts
- [ ] Review login history for compromised accounts for unauthorized access
- [ ] Check if compromised accounts were used for lateral movement
- [ ] Implement account lockout policy (lock after N failed attempts)
- [ ] Deploy rate limiting on all authentication endpoints
- [ ] Add CAPTCHA or anti-automation controls
- [ ] Consider implementing multi-factor authentication (MFA)

### Account Recovery Steps
```bash
# Lock compromised account (application-specific)
# UPDATE users SET locked=1 WHERE username='<compromised_user>';

# Force password reset
# UPDATE users SET password_expired=1 WHERE username='<compromised_user>';

# Revoke active sessions
# DELETE FROM sessions WHERE user_id=(SELECT id FROM users WHERE username='<compromised_user>');
```

## 5. Recovery
- [ ] Unlock accounts after users reset passwords via verified channels
- [ ] Monitor login activity for the next 72 hours
- [ ] Gradually remove IP blocks after monitoring period (7-14 days)
- [ ] Verify rate limiting is functioning correctly
- [ ] Confirm no unauthorized changes were made via compromised accounts
- [ ] Run credential stuffing test against patched endpoint to confirm mitigations

## 6. Lessons Learned
- [ ] Document timeline of attack and response
- [ ] Identify gaps in detection (time to detect, coverage)
- [ ] Measure: How many attempts before detection? How many accounts compromised?
- [ ] Review whether MFA would have prevented account compromise
- [ ] Assess password policy strength across the organization
- [ ] Check if any compromised passwords appeared in known breach databases (HaveIBeenPwned)

## 7. Prevention Measures
- Enforce multi-factor authentication (MFA) on all user accounts
- Implement rate limiting on all authentication endpoints
- Deploy account lockout after consecutive failed attempts
- Use CAPTCHA or proof-of-work challenges for login forms
- Monitor for credential dumps on dark web / threat intelligence feeds
- Implement password breach detection (check against known breach databases)
- Use device fingerprinting to detect automated login attempts
- Deploy Web Application Firewall (WAF) with credential stuffing rules
- Require unique, complex passwords and prohibit previously breached passwords
- Implement login anomaly detection (unusual IP, geolocation, time of day)
