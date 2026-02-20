# Incident Response Playbook: Drive-By Download Attack

## Scenario 18 - Drive-By Download

### Severity: HIGH
### MITRE ATT&CK: T1189 (Drive-By Compromise), T1203 (Exploitation for Client Execution), T1071.001 (Application Layer Protocol: Web)

---

## 1. Detection
- [ ] Suricata alert: Exploit kit landing page with hidden iframe (SID 9180001)
- [ ] Suricata alert: Exploit kit browser probing activity (SID 9180002)
- [ ] Suricata alert: Drive-by executable download (SID 9180004)
- [ ] Wazuh alert: Suspicious ad content with hidden iframe (rule 100560)
- [ ] Wazuh alert: Exploit kit browser fingerprinting (rule 100562)
- [ ] Wazuh alert: Drive-by download detected (rule 100564)
- [ ] Wazuh alert: Suspicious process launched by browser (rule 100566)
- [ ] Wazuh alert: C2 communication from payload (rule 100567)
- [ ] Web proxy logs show redirect chain from ad network to exploit kit
- [ ] Endpoint detection: unexpected executable in temp directory

## 2. Triage (First 15 minutes)
- [ ] Confirm the alert is a true positive (not a legitimate download)
- [ ] Identify the victim user and workstation
- [ ] Determine the exploit kit domain and infrastructure
- [ ] Check which vulnerability was exploited (CVE)
- [ ] Verify if the payload executed successfully
- [ ] Check for C2 communication from the victim host
- [ ] Determine if other users visited the same compromised site
- [ ] Check if the ad network compromise is ongoing (other sites affected)

## 3. Containment (First 30 minutes)
- [ ] **Immediate**: Kill the malicious process on the victim workstation
- [ ] **Immediate**: Block exploit kit domains at DNS/proxy level
- [ ] **Immediate**: Block payload delivery domain and IP
- [ ] **Immediate**: Block C2 server IP and domain
- [ ] Quarantine the downloaded payload file
- [ ] Remove persistence mechanisms (registry keys, startup items)
- [ ] Isolate victim workstation from network if C2 is confirmed
- [ ] Notify ad network provider of compromise

### Containment Commands
```bash
# Kill malicious process (Windows)
taskkill /IM kb5001330.exe /F

# Block domains at DNS level
echo "0.0.0.0 gate.exploitkit.test" >> /etc/hosts
echo "0.0.0.0 dl.softupdate.test" >> /etc/hosts

# Block attacker IPs at firewall
iptables -A INPUT -s <EXPLOIT_KIT_IP> -j DROP
iptables -A OUTPUT -d <C2_SERVER_IP> -j DROP

# Quarantine payload
move "%TEMP%\kb5001330.exe" C:\Quarantine\

# Remove registry persistence
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WindowsUpdateSvc /f

# Run containment script
python3 respond/containment.py
```

## 4. Eradication
- [ ] Remove all traces of the payload from the victim system
- [ ] Remove registry persistence entries
- [ ] Clear browser cache to remove exploit kit JavaScript
- [ ] Scan victim workstation with updated antivirus/EDR
- [ ] Check for additional payloads or second-stage malware
- [ ] Verify no lateral movement occurred from the victim host
- [ ] Block the compromised ad network across all proxy/DNS systems
- [ ] Update browser and all plugins to latest versions
- [ ] Deploy exploit kit detection signatures across the network

### Cleanup Steps
```bash
# Remove payload and related files
del /F /Q "%TEMP%\kb5001330.exe"
del /F /Q "%APPDATA%\Local\Temp\kb5001330.exe"

# Clear browser data
# Chrome: Settings -> Privacy -> Clear browsing data

# Full AV scan
MpCmdRun.exe -Scan -ScanType 2
```

## 5. Recovery
- [ ] Verify victim workstation is clean (re-image if uncertain)
- [ ] Update browser to latest version with all security patches
- [ ] Disable or remove unnecessary browser plugins (Flash, Java, Silverlight)
- [ ] Enable automatic browser updates
- [ ] Re-enable network access for the victim workstation
- [ ] Monitor the victim host for 72 hours for signs of re-infection
- [ ] Verify all exploit kit domains are blocked at network perimeter

## 6. Lessons Learned
- [ ] Document the complete attack chain from ad injection to payload execution
- [ ] Identify the compromised ad network and report to provider
- [ ] Assess browser patching cadence -- was the browser vulnerable?
- [ ] Evaluate whether web proxy/content filtering could have blocked the attack
- [ ] Review ad-blocking and script-blocking policies
- [ ] Measure time from compromise to detection
- [ ] Determine if other users were affected by the same campaign

## 7. Prevention Measures
- Deploy enterprise ad-blocking on all corporate browsers
- Keep browsers and plugins updated automatically
- Disable unnecessary browser plugins (Flash, Java applets, Silverlight)
- Implement Content Security Policy (CSP) headers on corporate sites
- Deploy web proxy with SSL inspection for download scanning
- Use browser isolation technology for high-risk browsing
- Enable browser sandboxing features (Chrome Site Isolation)
- Implement URL reputation checking at the proxy level
- Deploy endpoint detection and response (EDR) with exploit prevention
- Maintain DNS sinkhole for known exploit kit domains
- Consider network segmentation to limit C2 channel effectiveness
- Regular security awareness training on browsing risks
