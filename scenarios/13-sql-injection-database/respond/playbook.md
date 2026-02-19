# Incident Response Playbook: SQL Injection Attack

## Scenario 13 - SQL Injection Database Attack

### Severity: CRITICAL
### MITRE ATT&CK: T1190 (Exploit Public-Facing Application)

---

## 1. Detection
- [ ] Suricata alert: SQL injection patterns in HTTP traffic
- [ ] Wazuh alert: Web application attack correlation rule triggered
- [ ] Application logs show SQL error messages exposed to client
- [ ] Unusual database queries in slow query log

## 2. Triage (First 15 minutes)
- [ ] Confirm the alert is a true positive (not a scanner/WAF test)
- [ ] Identify source IP address and geolocation
- [ ] Determine which application/endpoint is being targeted
- [ ] Check if the attack was successful (data extracted)
- [ ] Assess scope: single endpoint vs. multiple attack vectors

## 3. Containment (First 30 minutes)
- [ ] **Immediate**: Block attacker IP at WAF/firewall level
- [ ] **Immediate**: Enable enhanced logging on affected application
- [ ] Rate limit the affected endpoint
- [ ] If data was extracted: identify what data was compromised
- [ ] Preserve evidence: capture network traffic, application logs, DB logs

### Containment Commands
```bash
# Block attacker IP (iptables)
iptables -A INPUT -s <ATTACKER_IP> -j DROP

# Block at Suricata (drop rule)
# Add to local.rules:
# drop http <ATTACKER_IP> any -> $SQL_SERVERS any (msg:"Block SQLi attacker"; sid:9999999;)

# Check for active sessions
netstat -an | grep <ATTACKER_IP>
```

## 4. Eradication
- [ ] Patch the vulnerable SQL query (use parameterized queries)
- [ ] Review all database queries in the application for similar flaws
- [ ] Remove any backdoor accounts created via SQLi
- [ ] Reset all database credentials
- [ ] If web shell was deployed: scan and remove
- [ ] Verify database integrity (compare with last known good backup)

### Code Fix Example
```python
# VULNERABLE (before)
query = f"SELECT * FROM users WHERE id='{user_input}'"

# SECURE (after)
query = "SELECT * FROM users WHERE id=?"
cursor.execute(query, (user_input,))
```

## 5. Recovery
- [ ] Restore database from backup if data was modified/deleted
- [ ] Re-deploy patched application
- [ ] Gradually remove IP blocks after monitoring period
- [ ] Verify all endpoints respond correctly
- [ ] Run automated SQLi scanner (sqlmap) against patched app to confirm fix

## 6. Lessons Learned
- [ ] Document timeline of attack and response
- [ ] Identify gaps in detection (time to detect, coverage)
- [ ] Update WAF rules to block common SQLi patterns
- [ ] Schedule developer training on secure coding practices
- [ ] Implement code review requirements for database queries
- [ ] Add SQLi to CI/CD security scanning pipeline

## 7. Prevention Measures
- Use parameterized queries / prepared statements everywhere
- Implement Web Application Firewall (WAF)
- Enable database query logging and monitoring
- Apply principle of least privilege for DB accounts
- Regular security scanning with tools like sqlmap, OWASP ZAP
- Input validation and output encoding
