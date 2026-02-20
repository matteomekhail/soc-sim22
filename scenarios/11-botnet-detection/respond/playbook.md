# Incident Response Playbook: Botnet Infection

## Scenario 11 - Botnet Detection

### Severity: CRITICAL
### MITRE ATT&CK: T1583.005 (Botnet), T1071.001 (Web Protocols), T1498 (Network DoS), T1059 (Command Interpreter), T1082 (System Info Discovery), T1210 (Exploitation of Remote Services)

---

## 1. Detection
- [ ] Wazuh alert: Worm-like SMB propagation across workstations (rule 100480)
- [ ] Wazuh alert: Bot registration with C2 server (rule 100481)
- [ ] Wazuh alert: Coordinated C2 beaconing from multiple internal hosts (rule 100482)
- [ ] Wazuh alert: Bot tasking commands received from C2 (rule 100483)
- [ ] Wazuh alert: DDoS traffic generation from internal host (rule 100484)
- [ ] Wazuh alert: Coordinated DDoS attack from botnet (rule 100485)
- [ ] Wazuh alert: Credential harvesting by bot (rule 100486)
- [ ] Wazuh alert: Data exfiltration by bot to C2 (rule 100487)
- [ ] Wazuh alert: Bot persistence mechanism installed (rule 100488)
- [ ] Wazuh alert: Botnet campaign correlated (rule 100489)
- [ ] Suricata alert: Worm propagation via SMB (SID 9110001)
- [ ] Suricata alert: Botnet C2 registration (SID 9110002)
- [ ] Suricata alert: Coordinated C2 beaconing (SID 9110003)
- [ ] Suricata alert: DDoS SYN flood from internal host (SID 9110004)
- [ ] Suricata alert: Botnet data exfiltration (SID 9110005)
- [ ] Network anomalies: Multiple internal hosts contacting same external IP at regular intervals

## 2. Triage (First 10 minutes)
- [ ] Confirm the alert is a true positive (not legitimate software update traffic)
- [ ] Identify patient zero -- the first infected workstation
- [ ] Determine the propagation method (SMB exploit, phishing, drive-by)
- [ ] Count the number of infected workstations
- [ ] Identify the C2 server IP and domain
- [ ] Determine if DDoS attack is active or pending
- [ ] Check if data exfiltration has occurred
- [ ] Assess scope: is the infection limited to one subnet or spreading further?
- [ ] Determine if credential harvesting has occurred (risk of further compromise)

## 3. Containment (First 15 minutes)
- [ ] **Immediate**: Isolate the infected network segment at the switch/firewall level
- [ ] **Immediate**: Block C2 server IP at perimeter firewall (ingress and egress)
- [ ] **Immediate**: Sinkhole C2 domain in internal DNS
- [ ] **Immediate**: Block DDoS target IP at egress to stop outbound attack
- [ ] Rate-limit outbound SYN packets from infected subnet
- [ ] Disable SMB (port 445) between workstations to stop further propagation
- [ ] Block data exfiltration endpoints at proxy/firewall

### Containment Commands
```bash
# Isolate infected segment
iptables -A FORWARD -s 10.0.0.100/28 -j DROP

# Block C2 server
iptables -A OUTPUT -d <C2_IP> -j DROP
iptables -A INPUT -s <C2_IP> -j DROP
iptables -A FORWARD -d <C2_IP> -j DROP

# Sinkhole C2 domain
echo '0.0.0.0 updates.evil-cdn.test' >> /etc/hosts

# Block DDoS traffic
iptables -A FORWARD -d <DDOS_TARGET_IP> -j DROP

# Block inter-workstation SMB
iptables -A FORWARD -s 10.0.0.0/24 -d 10.0.0.0/24 -p tcp --dport 445 -j DROP

# Run containment script
python3 respond/containment.py
```

## 4. Eradication
- [ ] Terminate bot processes on all infected hosts (`svchost_update.exe`, etc.)
- [ ] Remove scheduled task persistence (`schtasks /Delete /TN WindowsUpdateService /F`)
- [ ] Delete bot malware binaries from infected hosts
- [ ] Remove registry run keys added by bot
- [ ] Check for additional persistence: cron jobs, startup items, services
- [ ] Scan all infected hosts with updated antivirus/EDR
- [ ] Patch the SMB vulnerability that enabled propagation (e.g., MS17-010)
- [ ] Reset credentials for all users on infected workstations
- [ ] Check for lateral movement to servers (DC, file server, DB server)
- [ ] Verify no additional C2 channels exist (DNS tunneling, alternate IPs)
- [ ] Check if harvested credentials were used for further access

### Bot Cleanup per Host
```bash
# On each infected workstation:
taskkill /F /IM svchost_update.exe
schtasks /Delete /TN WindowsUpdateService /F
del /F C:\Windows\Temp\svchost_update.exe
reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v UpdateService /f

# Full antivirus scan
MpCmdRun.exe -Scan -ScanType 2

# Verify no remaining C2 connections
netstat -an | findstr <C2_IP>
```

## 5. Recovery
- [ ] Re-image severely infected workstations from known-good baseline
- [ ] Apply SMB security patches across all workstations
- [ ] Restore network connectivity incrementally (monitor for re-infection)
- [ ] Re-enable inter-workstation SMB only where business-required
- [ ] Verify all bot persistence mechanisms are removed
- [ ] Monitor recovered hosts for 72 hours for signs of re-infection
- [ ] Rotate all credentials for affected users
- [ ] Verify C2 domain remains sinkholed
- [ ] Confirm DDoS traffic has ceased

## 6. Lessons Learned
- [ ] Document complete timeline: initial infection to full containment
- [ ] Identify the initial infection vector (how did patient zero get compromised?)
- [ ] Assess why SMB exploitation was possible (missing patches? open ports?)
- [ ] Evaluate why C2 beaconing was not detected sooner
- [ ] Measure time from first infection to detection (dwell time)
- [ ] Measure time from detection to containment
- [ ] Count total number of infected hosts and credentials exposed
- [ ] Assess impact of the DDoS attack on the target
- [ ] Determine if exfiltrated credentials were used maliciously

## 7. Prevention Measures
- Deploy endpoint detection and response (EDR) on all workstations
- Segment the network to limit lateral movement (micro-segmentation)
- Apply SMB security patches promptly (patch management program)
- Disable SMBv1 across the environment
- Block unnecessary inter-workstation SMB traffic at the switch level
- Deploy network traffic analysis (NTA) to detect beaconing patterns
- Implement DNS monitoring to detect C2 domain lookups
- Configure egress filtering to block unauthorized outbound connections
- Deploy Suricata/Snort IDS with botnet detection rules
- Implement Wazuh FIM and active response for automated containment
- Conduct regular vulnerability scanning for exploitable services
- Use threat intelligence feeds to block known C2 infrastructure
- Rate-limit outbound SYN packets to mitigate DDoS participation
- Implement application whitelisting to prevent unauthorized executables
- Regular security awareness training for users (initial infection vector)
