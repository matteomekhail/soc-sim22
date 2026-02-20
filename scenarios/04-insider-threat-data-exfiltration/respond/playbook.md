# Incident Response Playbook: Insider Threat Data Exfiltration

## Scenario 04 - Insider Threat Data Exfiltration

### Severity: CRITICAL
### MITRE ATT&CK: T1567 (Exfiltration Over Web Service), T1048 (Exfiltration Over Alternative Protocol)
### Classification: CONFIDENTIAL - Restrict distribution to IR team, Legal, HR, and Management

---

## IMPORTANT: Legal Considerations

- **Do NOT** confront or alert the suspected insider until Legal counsel approves
- **Do NOT** discuss the investigation with colleagues outside the IR team
- **Document** every action taken with timestamps
- **Preserve** chain of custody for all evidence
- **Follow** applicable employment law and data privacy regulations

---

## 1. Detection Indicators

The following behavioral anomalies should trigger this playbook:

- [ ] After-hours access to sensitive file shares (HR, Finance, Executive)
- [ ] File access volume significantly exceeding user's normal baseline
- [ ] Access to directories outside the user's normal work scope
- [ ] Data staging activity (compression, archiving in temp directories)
- [ ] Large outbound HTTPS transfers to external/cloud destinations
- [ ] Asymmetric network flows (high upload, low download to external IPs)
- [ ] Anti-forensic behavior (deletion of staging files, log clearing)

### Detection Sources
| Source | Rule/Alert | Description |
|--------|-----------|-------------|
| Wazuh | 100400 | After-hours sensitive file access |
| Wazuh | 100401 | Bulk file access exceeding baseline |
| Wazuh | 100402 | Data staging (compression activity) |
| Wazuh | 100403 | Large outbound HTTPS transfer |
| Wazuh | 100405 | Correlated insider threat indicators |
| Suricata | 9040001 | Large outbound HTTPS transfer |
| Suricata | 9040002 | Multiple large uploads in short window |

---

## 2. Triage (First 15 minutes)

- [ ] **Confirm the alert** is a true positive (not scheduled backup, approved transfer)
- [ ] **Identify the user**: Username, department, role, manager, access level
- [ ] **Determine timing**: When did anomalous behavior start? Is it ongoing?
- [ ] **Assess scope**:
  - Which file shares/directories were accessed?
  - How many files were accessed or copied?
  - What data classifications are affected (PII, financial, strategic)?
- [ ] **Check for context**:
  - Is the user on a performance improvement plan or termination list?
  - Has the user recently given notice or been passed over for promotion?
  - Any recent disputes, complaints, or behavioral concerns?
- [ ] **Determine urgency**: Is exfiltration still in progress?

### Triage Decision Matrix

| Indicator | Response Level |
|-----------|---------------|
| After-hours access only | Monitor - Low |
| Bulk access + staging | Investigate - Medium |
| Active exfiltration in progress | Contain immediately - Critical |
| Exfiltration complete + cleanup | Contain + preserve - Critical |

---

## 3. Containment (First 30 minutes)

### Immediate Actions (if exfiltration is ongoing)

- [ ] **Disable user account** in Active Directory / LDAP

```powershell
# Windows AD
Disable-ADAccount -Identity "bob.wilson"
Set-ADAccountPassword -Identity "bob.wilson" -Reset -NewPassword (ConvertTo-SecureString "TempP@ss!Reset" -AsPlainText -Force)
```

- [ ] **Terminate VPN session** and revoke certificate

```bash
# Disconnect active session
ovpn-disconnect --user "bob.wilson" --server 10.0.1.30

# Revoke VPN certificate
ovpn-revoke-cert --user "bob.wilson" --crl-update
```

- [ ] **Block exfiltration destination** at perimeter firewall

```bash
# Block outbound to exfil destination
iptables -A OUTPUT -d 203.0.113.50 -j DROP
iptables -A FORWARD -d 203.0.113.50 -j DROP
```

- [ ] **Isolate workstation** from network (move to quarantine VLAN)

```bash
# Network isolation
iptables -A FORWARD -s 10.0.0.102 -j DROP
iptables -A FORWARD -d 10.0.0.102 -j DROP
# Allow forensic collection only
iptables -I FORWARD -s 10.0.0.102 -d 10.0.0.250 -j ACCEPT
```

### Evidence Preservation (Critical)

- [ ] **Do NOT** power off the workstation (preserve volatile memory)
- [ ] Capture RAM dump from insider's workstation
- [ ] Image the workstation hard drive (forensic copy)
- [ ] Export file server audit logs for the incident period
- [ ] Export VPN connection logs
- [ ] Export firewall/proxy logs for outbound traffic
- [ ] Export DNS query logs
- [ ] Capture network flow data (NetFlow/sFlow)
- [ ] Screenshot any active sessions before terminating

```bash
# Run containment script
python3 respond/containment.py
```

---

## 4. Investigation (Hours 1-24)

### Forensic Analysis

- [ ] **Timeline reconstruction**:
  - When did the insider first access sensitive directories?
  - What was the sequence of access, staging, and exfiltration?
  - Were there prior reconnaissance attempts (failed access, directory listings)?

- [ ] **Data impact assessment**:
  - Which specific files were accessed/copied? (file server audit trail)
  - What data classifications are involved?
  - Is PII/PHI/financial data affected (regulatory notification required)?
  - What is the business impact of this data being compromised?

- [ ] **Workstation forensics**:
  - Review bash/PowerShell history for staging commands
  - Check /tmp and temp directories for residual archives
  - Review browser history for cloud storage, file sharing, or email uploads
  - Check for USB device connection history
  - Review installed applications (cloud sync, FTP clients, VPN clients)
  - Check for encrypted containers or hidden partitions

- [ ] **Network forensics**:
  - Full packet capture analysis if available
  - DNS query analysis (resolve exfil destinations)
  - TLS certificate analysis on exfil connections
  - Check for alternative exfiltration channels (DNS tunneling, ICMP, steganography)

- [ ] **Exfiltration destination analysis**:
  - Who owns the destination IP/domain?
  - Is it a known cloud storage service?
  - Can law enforcement request data preservation from the provider?

### Scope Expansion Check

- [ ] Did the insider share credentials with anyone?
- [ ] Are there other accounts showing similar behavioral patterns?
- [ ] Did the insider access any other systems (databases, email, code repos)?
- [ ] Check for persistence mechanisms (backdoor accounts, scheduled tasks)

---

## 5. Eradication

- [ ] Remove any backdoor accounts or persistence mechanisms
- [ ] Rotate all credentials the insider had access to
- [ ] Rotate service account passwords if the insider had privileged access
- [ ] Review and revoke all access permissions associated with the user
- [ ] Remove the user from all groups, distribution lists, and shared resources
- [ ] Revoke API keys, tokens, and SSH keys
- [ ] Update file server ACLs to ensure principle of least privilege
- [ ] Review access of users with similar roles for overly broad permissions

---

## 6. Recovery

- [ ] Verify no data was modified (integrity check against backups)
- [ ] Restore any files that were altered or deleted
- [ ] Re-enable file server access with enhanced monitoring
- [ ] Implement additional DLP controls on sensitive file shares
- [ ] Deploy enhanced monitoring rules (see Wazuh rules 100400-100406)
- [ ] Gradually restore normal operations with increased audit logging

---

## 7. Notification and Reporting

### Internal Notifications (within 4 hours)
- [ ] HR department (employee relations)
- [ ] Legal counsel
- [ ] Executive management / CISO
- [ ] Affected data owners (HR director, CFO, CEO)

### External Notifications (as required by regulation)
- [ ] Data protection authority (if PII/GDPR data affected -- 72 hours)
- [ ] Affected individuals (if PII compromised)
- [ ] Law enforcement (if criminal activity suspected)
- [ ] Regulators (if financial/healthcare data affected)
- [ ] Cyber insurance carrier

---

## 8. Lessons Learned (Post-Incident)

- [ ] Conduct post-incident review within 5 business days
- [ ] Document complete incident timeline
- [ ] Identify detection gaps:
  - How long was the insider active before detection?
  - Which indicators were missed or delayed?
  - Were behavioral baselines properly configured?
- [ ] Improve detection capabilities:
  - Tune UEBA (User and Entity Behavior Analytics) thresholds
  - Add DLP rules for sensitive file shares
  - Implement mandatory access logging for sensitive directories
  - Consider deploying endpoint DLP agents
- [ ] Update policies:
  - Review acceptable use policy
  - Review data handling procedures
  - Update insider threat program documentation
  - Revise access provisioning procedures (least privilege)
- [ ] Training:
  - Security awareness training on insider threat indicators for managers
  - Technical training for SOC on behavioral anomaly detection

---

## 9. Prevention Measures

### Technical Controls
- Deploy Data Loss Prevention (DLP) on endpoints and network
- Implement User and Entity Behavior Analytics (UEBA)
- Enable mandatory file access auditing on all sensitive shares
- Restrict access to sensitive directories by role (RBAC)
- Block personal cloud storage services at the proxy
- Monitor for large outbound transfers (threshold alerting)
- Implement USB device control policies

### Administrative Controls
- Background checks for employees with access to sensitive data
- Separation of duties for critical data
- Regular access reviews (quarterly)
- Exit procedures that include immediate access revocation
- Employee monitoring disclosure (per legal requirements)
- Insider threat awareness program

### Process Controls
- Require manager approval for access to sensitive directories
- Time-bound access for temporary needs
- Automated detection of access pattern changes
- Regular review of file server access patterns vs. job requirements
