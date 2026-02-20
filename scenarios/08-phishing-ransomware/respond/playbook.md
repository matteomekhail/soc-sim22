# Incident Response Playbook: Phishing & Ransomware

## Scenario 08 - Phishing Email Leading to Ransomware Encryption

### Severity: CRITICAL
### MITRE ATT&CK: T1566.001 (Spearphishing Attachment), T1486 (Data Encrypted for Impact)

---

## 1. Detection

- [ ] Email gateway alert: phishing email with suspicious attachment (SPF/DKIM/DMARC failure)
- [ ] Suricata alert: suspicious executable download or macro-enabled document
- [ ] Wazuh FIM alert: mass file modifications in short time window
- [ ] Wazuh alert: ransomware file extension detected (.encrypted, .locked, .crypted)
- [ ] Wazuh alert: ransom note file created (RANSOM_NOTE.txt)
- [ ] Suricata alert: C2 communication to known bad IP
- [ ] User report: files inaccessible, ransom note displayed

## 2. Triage (First 10 minutes)

- [ ] Confirm the alert is a true positive (not a security drill or false positive)
- [ ] Identify the patient zero (first affected host and user)
- [ ] Determine the ransomware variant if possible (file extension, ransom note text)
- [ ] Check if encryption is still in progress or complete
- [ ] Assess scope: single host vs. lateral spread to network shares
- [ ] Check for C2 communication (outbound connections to external IPs)
- [ ] Escalate to Incident Commander and CISO

### Triage Questions
1. Which user opened the phishing attachment?
2. How many hosts are affected?
3. Are network shares (SMB/NFS) encrypted?
4. Is the encryption process still running?
5. Do we have recent backups of affected data?

## 3. Containment (First 30 minutes)

### 3a. Immediate Network Isolation
- [ ] **CRITICAL**: Disconnect affected host(s) from network immediately
- [ ] Block C2 server IP at firewall/proxy (203.0.113.100)
- [ ] Block phishing domain at DNS (acmecorp-login.test)
- [ ] Disable the affected user account
- [ ] Block lateral movement: isolate network segment

```bash
# Network isolation rules
iptables -A INPUT -s <VICTIM_IP> -j DROP
iptables -A OUTPUT -d <VICTIM_IP> -j DROP
iptables -A OUTPUT -d 203.0.113.100 -j DROP

# Block at DNS level
echo "0.0.0.0 updates.evil-cdn.test" >> /etc/hosts
echo "0.0.0.0 acmecorp-login.test" >> /etc/hosts
```

### 3b. Stop Encryption Process
- [ ] Kill the ransomware process on affected host(s)
- [ ] Remove persistence mechanisms (startup entries, scheduled tasks)

```bash
# Find and kill ransomware process
ps aux | grep -i 'svchost_update\|encrypt\|ransom'
pkill -9 -f svchost_update.exe

# Check for persistence
# Windows:
# reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
# schtasks /query /fo LIST /v | findstr svchost_update
# Linux:
# crontab -l | grep -i encrypt
# ls -la ~/.config/autostart/
```

### 3c. Preserve Evidence (Before Remediation)
- [ ] Image affected disk(s) for forensic analysis
- [ ] Capture memory dump of affected host
- [ ] Export all relevant logs (email, FIM, IDS, firewall)
- [ ] Save the ransomware binary for analysis
- [ ] Document the encryption key if found in memory or logs

## 4. Eradication

- [ ] Remove the ransomware binary and all dropped files
- [ ] Remove persistence mechanisms (registry, services, scheduled tasks)
- [ ] Scan all hosts in the network segment for indicators of compromise
- [ ] Block the phishing sender domain at the email gateway
- [ ] Update email filtering rules to catch similar attachments
- [ ] Update Suricata/Snort rules with new IOCs
- [ ] Quarantine the original phishing email from all mailboxes

### Indicators of Compromise (IOCs)
| Type | Value | Description |
|------|-------|-------------|
| IP | 203.0.113.50 | Attacker IP (phishing source) |
| IP | 203.0.113.100 | C2 server |
| Domain | updates.evil-cdn.test | C2 domain |
| Domain | acmecorp-login.test | Phishing domain |
| File | Invoice_2024.pdf.exe | Phishing attachment |
| File | svchost_update.exe | Ransomware payload |
| Extension | .encrypted | Encrypted file extension |
| File | RANSOM_NOTE.txt | Ransom note |

## 5. Recovery

### 5a. File Recovery Priority
1. **Encryption key recovery** -- check if key is in memory, logs, or C2 traffic capture
2. **Backup restoration** -- restore from last known good backup
3. **Shadow copy recovery** -- check if Volume Shadow Copies still exist
4. **Decryption tool** -- check NoMoreRansom.org for known decryptors

```bash
# Recovery with known key (WCACE simulation)
python3 respond/containment.py

# Restore from backup
# rsync -avz /backup/latest/ /data/restored/
```

### 5b. System Restoration
- [ ] Rebuild affected hosts from clean images if necessary
- [ ] Restore files from backup (verify integrity before restoration)
- [ ] Re-enable user accounts with mandatory password reset
- [ ] Gradually restore network connectivity with monitoring
- [ ] Verify all systems are functional and data is intact

## 6. Post-Incident Activities

### 6a. Lessons Learned (Within 1 week)
- [ ] Conduct post-incident review with all stakeholders
- [ ] Document complete timeline of the attack and response
- [ ] Identify detection gaps (time from initial infection to detection)
- [ ] Evaluate effectiveness of containment actions
- [ ] Assess backup adequacy and recovery time

### 6b. Preventive Measures
- [ ] Implement or enhance email attachment sandboxing
- [ ] Enable macro-blocking policy for Office documents from external sources
- [ ] Deploy endpoint detection and response (EDR) solution
- [ ] Conduct phishing awareness training for all employees
- [ ] Implement network segmentation to limit lateral movement
- [ ] Verify and test backup procedures (3-2-1 rule)
- [ ] Enable FIM monitoring on critical file shares
- [ ] Implement application whitelisting on endpoints

### 6c. Detection Improvements
- [ ] Add Suricata rules for ransomware C2 patterns (SID 9800001-9800006)
- [ ] Deploy Wazuh FIM rules for mass file modification (Rule 100300-100306)
- [ ] Set up email gateway alerting for failed SPF/DKIM/DMARC
- [ ] Create dashboard for ransomware indicators in Grafana
- [ ] Establish baseline for normal file modification rates

## 7. Communication Plan

| Audience | When | What |
|----------|------|------|
| SOC Team | Immediately | Alert triage and initial containment |
| IT Management | Within 15 min | Scope assessment and resource needs |
| CISO | Within 30 min | Incident severity and business impact |
| Legal/Compliance | Within 1 hour | Data breach assessment and notification requirements |
| Executive Team | Within 2 hours | Business impact summary and recovery timeline |
| Affected Users | After containment | Guidance on impacted files and recovery ETA |
| Law Enforcement | As appropriate | If ransom payment is considered or data theft confirmed |

## 8. Do NOT

- **DO NOT** pay the ransom without executive and legal approval
- **DO NOT** attempt to negotiate with attackers without guidance
- **DO NOT** connect affected hosts back to the network before full scan
- **DO NOT** delete the ransomware binary (preserve for forensics)
- **DO NOT** rely solely on decryption -- verify file integrity after recovery
- **DO NOT** assume only one host is affected -- scan the entire segment
