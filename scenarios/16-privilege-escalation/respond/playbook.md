# Incident Response Playbook: Privilege Escalation Attack

## Scenario 16 - Privilege Escalation

### Severity: CRITICAL
### MITRE ATT&CK: T1068 (Exploitation for Privilege Escalation), T1548 (Abuse Elevation Control), T1136.001 (Create Account: Local Account)

---

## 1. Detection
- [ ] Wazuh alert: Unauthorized sudo attempt - user not in sudoers (rule 100540)
- [ ] Wazuh alert: Multiple unauthorized sudo attempts from same user (rule 100541)
- [ ] Wazuh alert: SUID binary enumeration detected (rule 100542)
- [ ] Wazuh alert: SUID binary exploited for root access (rule 100543)
- [ ] Wazuh alert: Root session opened by non-admin user (rule 100544)
- [ ] Wazuh alert: New admin account created (rule 100546)
- [ ] Wazuh alert: Sudoers file modified with NOPASSWD (rule 100547)
- [ ] Suricata alert: Outbound connection from escalated process (SID 9160001)
- [ ] Auth log anomalies: non-admin user gaining root access

## 2. Triage (First 10 minutes)
- [ ] Confirm the alert is a true positive (not a legitimate admin action)
- [ ] Identify the compromised user account
- [ ] Determine the escalation method (sudo abuse, SUID exploitation, kernel exploit)
- [ ] Check if root access was successfully obtained
- [ ] Identify any new accounts created (backdoors)
- [ ] Check for lateral movement from the escalated session
- [ ] Determine the initial access vector (how was the user account compromised?)

## 3. Containment (First 15 minutes)
- [ ] **Immediate**: Kill all sessions from the attacker IP
- [ ] **Immediate**: Lock the compromised user account
- [ ] **Immediate**: Lock any backdoor accounts created
- [ ] **Immediate**: Remove unauthorized sudoers entries
- [ ] Block attacker IP at firewall
- [ ] Isolate the affected server from the network if lateral movement detected

### Containment Commands
```bash
# Kill attacker sessions
ss -K dst <ATTACKER_IP>
pkill -u <COMPROMISED_USER>

# Lock compromised account
usermod -L <COMPROMISED_USER>

# Lock backdoor account
usermod -L <BACKDOOR_USER>
chage -E 0 <BACKDOOR_USER>

# Remove sudoers backdoor
rm -f /etc/sudoers.d/<BACKDOOR_USER>

# Block attacker IP
iptables -A INPUT -s <ATTACKER_IP> -j DROP

# Run containment script
python3 respond/containment.py
```

## 4. Eradication
- [ ] Remove the backdoor user account entirely (`userdel -r <BACKDOOR_USER>`)
- [ ] Remove SUID bit from misconfigured binaries (`chmod u-s <BINARY>`)
- [ ] Audit all SUID/SGID binaries: `find / -perm -4000 -o -perm -2000 -type f 2>/dev/null`
- [ ] Review and harden `/etc/sudoers` and `/etc/sudoers.d/`
- [ ] Check for cron jobs, systemd services, or other persistence mechanisms
- [ ] Review SSH authorized_keys files for unauthorized entries
- [ ] Check for modified system binaries (rootkit detection): `debsums -c` or `rpm -Va`
- [ ] Scan for additional backdoors: `find / -newer /etc/sudoers -type f 2>/dev/null`
- [ ] Change passwords for all accounts on the affected system
- [ ] Rotate SSH host keys

### SUID Remediation
```bash
# Remove SUID from commonly abused binaries
chmod u-s /usr/bin/find
chmod u-s /usr/bin/vim.basic
chmod u-s /usr/bin/nmap
chmod u-s /usr/bin/python3
chmod u-s /usr/bin/env

# Set proper SUID only on required binaries
# (su, sudo, passwd, ping, mount, umount)
```

## 5. Recovery
- [ ] Re-enable the compromised user account with a new password
- [ ] Verify all backdoor accounts and persistence mechanisms are removed
- [ ] Restore system files from known-good backup if integrity is uncertain
- [ ] Re-audit SUID/SGID binaries against baseline
- [ ] Monitor the system for 72 hours for signs of re-compromise
- [ ] Verify PAM configuration is hardened
- [ ] Enable enhanced audit logging (`auditd`) for privileged commands

## 6. Lessons Learned
- [ ] Document complete timeline of the attack
- [ ] Identify how the initial user account was compromised
- [ ] Assess why SUID binaries were misconfigured
- [ ] Review sudoers policy -- who has sudo access and why
- [ ] Evaluate whether FIM (File Integrity Monitoring) detected the changes in time
- [ ] Measure time from initial access to root access (dwell time)
- [ ] Measure time from root access to detection

## 7. Prevention Measures
- Implement principle of least privilege for all user accounts
- Regularly audit SUID/SGID binaries against an approved baseline
- Use `auditd` to monitor sudo usage and privilege changes
- Implement Wazuh FIM on critical files (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`)
- Restrict `su` command to wheel group (`pam_wheel.so`)
- Configure PAM to rate-limit failed sudo attempts
- Deploy SELinux or AppArmor to restrict binary capabilities
- Use AIDE or OSSEC for file integrity monitoring
- Implement centralized logging for auth events
- Regular penetration testing to identify misconfigured SUID binaries
- Consider using `nosuid` mount option on non-essential filesystems
