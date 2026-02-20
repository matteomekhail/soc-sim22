# Incident Response Playbook: APT with Remote Access Trojan

## Scenario 10 - Python RAT with C2 Beaconing

### Severity: CRITICAL
### MITRE ATT&CK: T1219 (Remote Access Software), T1071 (Application Layer Protocol), T1059.006 (Python), T1053.003 (Cron), T1041 (Exfiltration Over C2 Channel)

---

## 1. Detection
- [ ] Wazuh alert: Python process spawned from document handler (rule 100460)
- [ ] Wazuh alert: RAT installation with persistence mechanism (rule 100461)
- [ ] Wazuh alert: C2 beaconing pattern detected (rule 100462)
- [ ] Wazuh alert: RAT command execution via C2 (rule 100463)
- [ ] Wazuh alert: Data exfiltration over C2 channel (rule 100466)
- [ ] Suricata alert: Regular interval HTTPS beaconing (SID 9100001)
- [ ] Suricata alert: C2 domain DNS lookup (SID 9100005)
- [ ] Network flow analysis: Regular-interval outbound HTTPS connections
- [ ] EDR alert: Python process with suspicious parent chain

## 2. Triage (First 15 minutes)
- [ ] Confirm the process chain is malicious (document handler -> python -> network)
- [ ] Identify the C2 server IP and domain
- [ ] Analyze beacon interval pattern (statistical regularity test)
- [ ] Determine what commands have been executed via the RAT
- [ ] Check if credentials or sensitive data have been exfiltrated
- [ ] Identify the initial delivery vector (phishing email)
- [ ] Check if other workstations show similar beaconing patterns
- [ ] Assess data at risk based on user's access level

## 3. Containment (First 30 minutes)

### 3a. Immediate Host Containment
- [ ] **Kill the RAT process** (pkill -9 -f 'sys_update')
- [ ] **Do NOT reboot** (crontab will restart RAT; remove persistence first)
- [ ] **Remove persistence** (crontab entry + .bashrc modification)
- [ ] **Delete RAT files** from installation directory
- [ ] **Quarantine the workstation** from the network

### 3b. Network Containment
- [ ] **Block C2 server IP** at perimeter firewall (ingress and egress)
- [ ] **Block C2 domain** at DNS level (sinkhole or blackhole)
- [ ] **Block the phishing sender domain** in email gateway

### 3c. Credential Containment
- [ ] **Force password reset** for the victim user
- [ ] **Regenerate SSH keys** (private key was exfiltrated)
- [ ] **Clear browser saved passwords** (may have been captured)
- [ ] **Revoke all active sessions** for the victim user

### Containment Commands
```bash
# Kill RAT
pkill -9 -f 'sys_update'

# Remove persistence
crontab -u carlos.garcia -l | grep -v 'sys_update' | crontab -u carlos.garcia -
sed -i '/sys_update/d' /home/carlos.garcia/.bashrc
rm -rf /home/carlos.garcia/.local/share/.sys_update/

# Block C2
iptables -A OUTPUT -d 203.0.113.100 -j DROP
echo '127.0.0.1 updates.evil-cdn.test' >> /etc/hosts

# Quarantine workstation
iptables -A FORWARD -s 10.0.0.104 -j DROP

# Run automated containment
python3 respond/containment.py
```

## 4. Eradication

### 4a. Malware Removal
- [ ] Verify all RAT processes are terminated
- [ ] Remove ALL persistence mechanisms (cron, bashrc, autostart, systemd)
- [ ] Search for additional dropped files or secondary payloads
- [ ] Check for rootkit or kernel-level persistence
- [ ] Scan with updated AV/EDR signatures

### 4b. Credential Recovery
- [ ] Change passwords for ALL accounts the victim had access to
- [ ] Rotate any service account credentials the user could view
- [ ] Invalidate any API tokens or session cookies
- [ ] Check if exfiltrated credentials were used elsewhere

### 4c. Email Security
- [ ] Block the phishing sender and domain
- [ ] Search for similar phishing emails sent to other users
- [ ] Update email filtering rules for .xlsm attachments with macros
- [ ] Notify all recipients of the phishing campaign

```bash
# Full malware scan
find /home/carlos.garcia -name '*.py' -newer /home/carlos.garcia/.bashrc -exec file {} \;
find /tmp -name '.*' -type f -exec ls -la {} \;
rkhunter --check
```

## 5. Recovery
- [ ] Consider reimaging the workstation from clean image
- [ ] Restore user data from pre-compromise backup
- [ ] Re-enable network access with enhanced monitoring
- [ ] Implement application whitelisting to prevent unauthorized Python execution
- [ ] Monitor for C2 reconnection attempts for 30 days
- [ ] Verify no other workstations are compromised with same RAT

## 6. Lessons Learned
- [ ] Document the phishing email IOCs (sender, subject, attachment hash)
- [ ] Document the RAT IOCs (file paths, C2 domain/IP, beacon interval)
- [ ] Assess time from delivery to detection (dwell time)
- [ ] Determine what data was exfiltrated before containment
- [ ] Evaluate why the phishing email bypassed email security
- [ ] Assess whether macro execution should be disabled organization-wide
- [ ] Review user awareness training effectiveness

## 7. Prevention Measures
- Disable macro execution in Office documents by default (GPO)
- Block .xlsm and other macro-enabled attachments at email gateway
- Implement application whitelisting (prevent unauthorized Python execution)
- Deploy EDR with behavioral detection (process chain analysis)
- Implement network traffic analysis for beaconing detection (JA3/JA4 fingerprinting)
- Enable DNS logging and monitoring for known-bad domains
- Deploy outbound TLS inspection for C2 traffic analysis
- Conduct regular phishing simulation and awareness training
- Implement least privilege for user workstations
- Use browser password managers instead of built-in browser storage
- Monitor for data staging patterns (large archive creation in user dirs)
