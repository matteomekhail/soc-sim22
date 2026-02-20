# Incident Response Playbook: Watering Hole Attack

## Scenario 12 - Watering Hole Attack: Website Compromise to Post-Exploitation

### Severity: CRITICAL
### MITRE ATT&CK: T1189 (Drive-by Compromise), T1203 (Exploitation for Client Execution), T1547.001 (Registry Run Keys), T1071.001 (Application Layer Protocol), T1082 (System Information Discovery)

---

## 1. Detection

- [ ] Suricata alert: Suspicious web application modification from external IP (SID 9120001)
- [ ] Suricata alert: Browser exploit kit delivery detected (SID 9120002)
- [ ] Suricata alert: C2 beacon from compromised host (SID 9120003)
- [ ] Suricata alert: Post-exploitation reconnaissance activity (SID 9120004)
- [ ] Suricata alert: Suspicious data exfiltration to C2 (SID 9120005)
- [ ] Wazuh alert: Web application modification on industry site (Rule 100500)
- [ ] Wazuh alert: Multiple employees visiting suspected watering hole (Rule 100501)
- [ ] Wazuh alert: Browser exploitation attempt detected (Rule 100502)
- [ ] Wazuh alert: Drive-by download of suspicious file (Rule 100503)
- [ ] Wazuh alert: Registry run key persistence added (Rule 100504)
- [ ] Wazuh alert: C2 communication from compromised host (Rule 100505)
- [ ] Wazuh alert: System reconnaissance commands executed (Rule 100506)
- [ ] Wazuh alert: Credential harvesting (LSASS dump) detected (Rule 100507)
- [ ] Wazuh alert: Data exfiltration to C2 (Rule 100508)
- [ ] Wazuh correlation: Full watering hole kill chain detected (Rule 100509)
- [ ] User report: unexpected browser crashes or slow performance
- [ ] Threat intel feed: compromised website reported by third party

## 2. Triage (First 10 minutes)

- [ ] Confirm the alert is a true positive (not a false positive or security drill)
- [ ] Identify the compromised website and confirm it is a watering hole
- [ ] Determine which employees visited the compromised site (web proxy logs)
- [ ] Identify which workstations were successfully exploited (C2 beacons)
- [ ] Assess the browser vulnerability being exploited (CVE identification)
- [ ] Check for C2 communication from internal hosts to external IPs
- [ ] Determine if lateral movement has occurred from compromised hosts
- [ ] Escalate to Incident Commander and CISO

### Triage Questions
1. Which website was compromised, and how was it identified?
2. How many employees visited the site during the compromise window?
3. Which workstations show C2 communication or exploit indicators?
4. What browser vulnerability is being exploited (is a patch available)?
5. Is there evidence of lateral movement from compromised hosts?
6. Has any data been exfiltrated via the C2 channel?

## 3. Containment (First 30 minutes)

### 3a. Block the Compromised Website
- [ ] **IMMEDIATE**: Block the compromised website at DNS and web proxy
- [ ] Notify the website owner/operator of the compromise
- [ ] Add the website to threat intelligence blocklists

```bash
# DNS sinkhole
echo "0.0.0.0 news-portal.test" >> /etc/hosts

# Proxy blocklist
# squid: acl blocked_watering_hole dstdomain news-portal.test
# squid: http_access deny blocked_watering_hole

# Firewall block of website IP
iptables -A OUTPUT -d 198.51.100.25 -j DROP
iptables -A FORWARD -d 198.51.100.25 -j DROP
```

### 3b. Isolate Compromised Workstations
- [ ] **CRITICAL**: Disconnect all confirmed-compromised hosts from the network
- [ ] Isolate at switch port level if possible (not just firewall)
- [ ] Preserve running state for forensic memory capture before shutdown

```bash
# Network isolation for each compromised host
iptables -A INPUT -s <VICTIM_IP> -j DROP
iptables -A OUTPUT -d <VICTIM_IP> -j DROP
iptables -A FORWARD -s <VICTIM_IP> -j DROP
```

### 3c. Block C2 Communication
- [ ] Block C2 server IP at perimeter firewall and proxy
- [ ] Block C2 domain at DNS
- [ ] Block the attacker IP that compromised the website

```bash
# Block C2 server
iptables -A OUTPUT -d 203.0.113.100 -j DROP
iptables -A FORWARD -d 203.0.113.100 -j DROP

# Block C2 domain
echo "0.0.0.0 updates.evil-cdn.test" >> /etc/hosts

# Block attacker IP
iptables -A INPUT -s 203.0.113.50 -j DROP
iptables -A FORWARD -s 203.0.113.50 -j DROP
```

### 3d. Quarantine Exposed (Non-Exploited) Hosts
- [ ] Identify all hosts that visited the compromised website
- [ ] Place exposed-but-not-exploited hosts on a quarantine VLAN
- [ ] Run IOC scans before returning to production network

### 3e. Preserve Evidence (Before Remediation)
- [ ] Capture memory dump of compromised workstations
- [ ] Image affected disks for forensic analysis
- [ ] Export web proxy logs showing visits to compromised site
- [ ] Export IDS/IPS alerts and SIEM logs
- [ ] Capture network traffic (PCAP) for C2 analysis
- [ ] Save the malware payload for reverse engineering

## 4. Eradication

- [ ] Remove the malware payload from all compromised hosts
  - Delete `msedge_update.exe` from `%TEMP%` and `%APPDATA%`
- [ ] Remove persistence mechanisms
  - Delete registry run key: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\EdgeUpdate`
- [ ] Remove any credential harvesting artifacts (LSASS dump files)
- [ ] Reset credentials for all users on compromised workstations
- [ ] Reset credentials for any domain accounts accessed from compromised hosts
- [ ] Patch the exploited browser vulnerability (CVE-2024-4761)
- [ ] Scan all workstations in the network for IOCs
- [ ] Update Suricata/Wazuh rules with new indicators

```bash
# On each compromised Windows host:
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v EdgeUpdate /f
del /f /q "%APPDATA%\msedge_update.exe"
del /f /q "%TEMP%\msedge_update.exe"
taskkill /f /im msedge_update.exe

# Reset user passwords
net user <username> * /domain
```

### Indicators of Compromise (IOCs)
| Type | Value | Description |
|------|-------|-------------|
| IP | 203.0.113.50 | Attacker IP (website compromise) |
| IP | 203.0.113.100 | C2 server |
| IP | 198.51.100.25 | Compromised website IP |
| Domain | news-portal.test | Compromised watering hole website |
| Domain | updates.evil-cdn.test | C2 domain |
| URL | /assets/js/analytics-v3.min.js | Injected malicious JavaScript |
| URL | /api/v2/content/feed | Exploit kit delivery endpoint |
| File | msedge_update.exe | Malware payload |
| Hash | b3a4f7e2c1d8000...000 | Payload SHA-256 hash |
| Registry | HKCU\..\Run\EdgeUpdate | Persistence run key |
| CVE | CVE-2024-4761 | Exploited browser vulnerability |

## 5. Recovery

### 5a. Workstation Recovery
1. **Patch browsers** -- deploy CVE-2024-4761 fix to all workstations immediately
2. **Rebuild compromised hosts** -- reimage from clean baseline if full eradication cannot be confirmed
3. **Credential rotation** -- force password reset for all affected users and privileged accounts
4. **Restore from backup** -- if any data was corrupted or tampered with
5. **Gradual reconnection** -- return hosts to production with enhanced monitoring

### 5b. Website Remediation (Coordinate with Website Owner)
- [ ] Notify website owner with details of the compromise
- [ ] Provide IOCs and malicious code samples
- [ ] Verify the website is cleaned before unblocking
- [ ] Continue monitoring for re-compromise

### 5c. Verification
- [ ] Confirm no C2 beacons from any internal host
- [ ] Verify all persistence mechanisms are removed
- [ ] Run full vulnerability scan on all endpoints
- [ ] Confirm browser patches are deployed organization-wide
- [ ] Monitor for any re-infection indicators for 30 days

## 6. Post-Incident Activities

### 6a. Lessons Learned (Within 1 week)
- [ ] Conduct post-incident review with all stakeholders
- [ ] Document complete attack timeline (compromise window, detection time, response time)
- [ ] Identify detection gaps (how long was the watering hole active before detection?)
- [ ] Evaluate effectiveness of web proxy and DNS security controls
- [ ] Assess browser patching cadence and vulnerability management
- [ ] Review employee web browsing policies

### 6b. Preventive Measures
- [ ] Implement browser isolation for high-risk web categories
- [ ] Deploy web content filtering with JavaScript analysis
- [ ] Enable automatic browser patching (Chrome/Edge enterprise policies)
- [ ] Implement DNS security (DNSSEC, DNS-over-HTTPS with filtering)
- [ ] Deploy network-based exploit detection (IPS in-line mode)
- [ ] Consider web application firewall (WAF) for partner/industry sites
- [ ] Implement endpoint detection and response (EDR) with exploit protection
- [ ] Conduct security awareness training on watering hole attack risks
- [ ] Establish threat intelligence sharing with industry peers

### 6c. Detection Improvements
- [ ] Add Suricata rules for exploit kit patterns (SID 9120001-9120005)
- [ ] Deploy Wazuh rules for watering hole indicators (Rule 100500-100509)
- [ ] Create Grafana dashboard for watering hole indicators
- [ ] Set up alerting for anomalous JavaScript downloads from visited sites
- [ ] Monitor for new registry run key additions across all endpoints
- [ ] Baseline normal browsing patterns to detect anomalous site visits
- [ ] Integrate with threat intel feeds for known compromised websites

## 7. Communication Plan

| Audience | When | What |
|----------|------|------|
| SOC Team | Immediately | Alert triage and initial containment |
| IT Management | Within 15 min | Scope: number of affected hosts and users |
| CISO | Within 30 min | Attack type, severity, and containment status |
| Legal/Compliance | Within 1 hour | Data exposure assessment, notification requirements |
| Executive Team | Within 2 hours | Business impact and recovery timeline |
| Affected Users | After containment | Guidance: password reset, browser updates, what to expect |
| Website Owner | Immediately | Notification of compromise with IOC details |
| Industry ISAC | Within 24 hours | Threat intelligence sharing for sector awareness |

## 8. Do NOT

- **DO NOT** continue visiting the compromised website for "investigation" from production hosts
- **DO NOT** reconnect compromised hosts before full eradication is confirmed
- **DO NOT** assume only browser-exploited hosts are affected -- scan all visitors
- **DO NOT** delete malware samples before forensic preservation
- **DO NOT** rely on antivirus alone -- watering hole payloads are often zero-day or FUD
- **DO NOT** unblock the website until the owner confirms remediation
- **DO NOT** skip credential rotation for users on compromised hosts
