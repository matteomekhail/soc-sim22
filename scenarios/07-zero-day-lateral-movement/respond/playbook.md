# Incident Response Playbook: Zero-Day Exploit & Lateral Movement

## Scenario 07 - Zero-Day with Domain-Wide Lateral Movement

### Severity: CRITICAL
### MITRE ATT&CK: T1068 (Exploitation for Privilege Escalation), T1021 (Remote Services), T1059 (Command Interpreter), T1018 (Remote System Discovery), T1003 (OS Credential Dumping)

---

## 1. Detection
- [ ] Wazuh alert: Anomalous process crash on application server (rule 100440)
- [ ] Wazuh alert: Unexpected shell spawn from service process (rule 100441)
- [ ] Wazuh alert: Internal network reconnaissance from compromised host (rule 100442)
- [ ] Wazuh alert: Credential harvesting detected (rule 100443)
- [ ] Wazuh alert: Sequential SSH lateral movement pattern (rule 100444)
- [ ] Wazuh alert: SMB administrative share access (rule 100445)
- [ ] Wazuh alert: Mass credential extraction from DC (rule 100448)
- [ ] Suricata alert: Internal scan from DMZ host (SID 9070001)
- [ ] Suricata alert: Sequential SSH access pattern (SID 9070002)
- [ ] Anomalous outbound connection from API server on non-standard port

## 2. Triage (First 15 minutes)
- [ ] Confirm the application crash is exploit-related (not a bug)
- [ ] Identify if the exploit uses a known or unknown vulnerability (zero-day assessment)
- [ ] Determine the initial access point and current attacker position
- [ ] Map the full compromise chain (which hosts have been accessed)
- [ ] Check if domain credentials or AD database have been extracted
- [ ] Assess whether data exfiltration has occurred
- [ ] Escalate immediately to CISO and activate full IR team
- [ ] Contact vendor/CERT if zero-day confirmed

## 3. Containment (First 30 minutes)

### 3a. Immediate Network Containment
- [ ] **Isolate ALL hosts in the compromise chain** from the network
- [ ] **Block DMZ-to-internal traffic** entirely (emergency segmentation)
- [ ] **Block the attacker's external IP** at perimeter firewall
- [ ] **Block the reverse shell port** (4444) outbound
- [ ] **Do NOT power off hosts** -- preserve volatile memory evidence

### 3b. Identity Containment
- [ ] **Expire ALL compromised account passwords** immediately
- [ ] **Rotate the krbtgt password TWICE** (golden ticket mitigation)
- [ ] **Revoke all Kerberos tickets** across the domain
- [ ] **Regenerate SSH host keys** on all compromised hosts
- [ ] **Disable service accounts** used in lateral movement

### 3c. Domain Containment
- [ ] **Remove any malicious GPOs** created by the attacker
- [ ] **Audit all recent AD changes** (new users, group memberships, GPOs)
- [ ] **Enable enhanced audit logging** on the domain controller

### Containment Commands
```bash
# Isolate compromise chain (run on firewall)
for host in 10.0.1.20 10.0.0.100 10.0.0.101 10.0.0.103 10.0.0.30 10.0.0.105 10.0.0.20 10.0.0.10; do
  iptables -A FORWARD -s $host -j DROP
  iptables -A FORWARD -d $host -j DROP
done

# Block DMZ to internal
iptables -A FORWARD -s 10.0.1.0/24 -d 10.0.0.0/24 -j DROP

# Rotate krbtgt (run TWICE, 12 hours apart)
samba-tool user setpassword krbtgt --newpassword="$(openssl rand -base64 32)"

# Run automated containment
python3 respond/containment.py
```

## 4. Eradication

### 4a. Zero-Day Remediation
- [ ] Identify the exact vulnerability and create a temporary mitigation
- [ ] Disable the vulnerable API endpoint until patched
- [ ] Deploy WAF rules to block the exploit payload pattern
- [ ] Report the zero-day to the software vendor
- [ ] Monitor for public disclosure and patch availability

### 4b. Host Cleanup (for each compromised host)
- [ ] Capture memory dump before cleanup
- [ ] Remove attacker tools, scripts, and backdoors
- [ ] Remove persistence mechanisms (crontab, startup scripts, SSH keys)
- [ ] Verify system integrity against known-good baselines
- [ ] Consider full rebuild from clean images for critical servers

### 4c. Domain Cleanup
- [ ] Audit all AD objects modified during the attack window
- [ ] Remove unauthorized user accounts, group memberships, and GPOs
- [ ] Verify SYSVOL and NETLOGON share integrity
- [ ] Reset ALL domain user passwords (phased rollout)
- [ ] Re-enable enhanced auditing permanently

## 5. Recovery
- [ ] Rebuild compromised API server from clean image with vulnerability mitigated
- [ ] Restore internal hosts from verified clean backups
- [ ] Implement proper DMZ segmentation (no direct SSH/SMB from DMZ to internal)
- [ ] Deploy the vendor patch when available
- [ ] Re-enable network connectivity in stages with enhanced monitoring
- [ ] Monitor for attacker return using IOCs for 90 days (zero-day warrants longer)
- [ ] Perform full vulnerability assessment on all DMZ-facing services

## 6. Lessons Learned
- [ ] Document the zero-day details for threat intelligence sharing (STIX/TAXII)
- [ ] Calculate total dwell time and time-to-contain
- [ ] Map the full kill chain and identify detection gaps at each phase
- [ ] Assess why DMZ-to-internal lateral movement was possible
- [ ] Review service account privilege levels (did svc_web need sudo?)
- [ ] Evaluate detection capability for unknown/zero-day exploits
- [ ] Assess whether network segmentation would have limited blast radius

## 7. Prevention Measures
- Implement strict network segmentation (DMZ cannot reach internal hosts directly)
- Deploy EDR on all servers for behavioral-based zero-day detection
- Enforce least privilege for service accounts (no sudo, minimal SSH access)
- Implement just-in-time access for administrative tasks
- Deploy application-level firewalls with anomaly detection
- Enable crash dump analysis and monitoring for exploitation indicators
- Implement network flow analysis for lateral movement detection
- Regular red team exercises simulating zero-day + lateral movement scenarios
- Deploy deception technology (honeypots) in lateral movement paths
- Enforce MFA on all SSH and SMB access to critical servers
