# Incident Response Playbook: Cryptojacking

## Scenario 19 - Browser-Based Cryptocurrency Mining

### Severity: HIGH
### MITRE ATT&CK: T1496 (Resource Hijacking), T1071 (Application Layer Protocol)

---

## 1. Detection
- [ ] Suricata alert: Connections to known mining pool IPs/domains
- [ ] Suricata alert: CoinHive or crypto miner JavaScript in HTTP traffic
- [ ] Suricata alert: Stratum mining protocol on port 3333/3334
- [ ] Wazuh alert: Sustained high CPU usage from browser processes
- [ ] Wazuh alert: Multiple hosts connecting to mining pools
- [ ] User complaints: Slow computer performance, high fan noise
- [ ] Network monitoring: Unusual sustained outbound connections

## 2. Triage (First 15 minutes)
- [ ] Confirm the alert is a true positive (not legitimate mining software)
- [ ] Identify affected workstations/hosts (source IPs in alerts)
- [ ] Determine the infection vector (compromised website, malicious ad, extension)
- [ ] Identify the mining pool being connected to (IP, domain, port)
- [ ] Assess scope: single user vs. multiple users/departments
- [ ] Check if the compromised website is an internal or external resource

## 3. Containment (First 30 minutes)

### Immediate Actions
- [ ] **Block mining pool IP** at perimeter firewall (all ports)
- [ ] **DNS sinkhole** the mining pool domain
- [ ] **Block stratum ports** (3333, 3334) at firewall for all outbound traffic
- [ ] **Notify affected users** to close the compromised website tab/browser

### Containment Commands
```bash
# Block mining pool IP at firewall
iptables -A OUTPUT -d <MINING_POOL_IP> -j DROP
iptables -A FORWARD -d <MINING_POOL_IP> -j DROP

# Block stratum protocol ports (outbound)
iptables -A OUTPUT -p tcp --dport 3333 -j DROP
iptables -A OUTPUT -p tcp --dport 3334 -j DROP

# DNS sinkhole (add to DNS server or /etc/hosts)
echo "127.0.0.1 pool.cryptomine.test" >> /etc/hosts

# Kill browser processes on affected workstations (if needed)
# taskkill /F /IM chrome.exe  (Windows)
# pkill -f chrome             (Linux)

# Check for active connections to mining pools
netstat -an | grep -E ':3333|:3334'
ss -tnp | grep -E ':3333|:3334'
```

### Suricata Drop Rules
```
drop tcp $HOME_NET any -> <MINING_POOL_IP> any (msg:"Block mining pool"; sid:9199001;)
drop tcp $HOME_NET any -> $EXTERNAL_NET 3333:3334 (msg:"Block stratum"; sid:9199002;)
```

## 4. Eradication

### If the source is a compromised website (server-side)
- [ ] Identify the injected JavaScript in the website source code
- [ ] Remove the `<script>` tag loading coinhive/miner JS
- [ ] Check for server-side injection (PHP, Python, Node.js includes)
- [ ] Scan web server for web shells or backdoors
- [ ] Determine how the website was compromised (CMS vulnerability, stolen credentials)
- [ ] Patch the vulnerability that allowed the injection

### If the source is a browser extension
- [ ] Identify the malicious extension across all affected workstations
- [ ] Force-remove the extension via group policy or MDM
- [ ] Block the extension ID in browser management policies

### If the source is a malicious advertisement (malvertising)
- [ ] Block the ad network domain serving the malicious ad
- [ ] Deploy ad blockers on corporate browsers
- [ ] Contact the ad network to report the malicious creative

### Scan Commands
```bash
# Search web server for injected mining code
grep -rl 'coinhive\|CoinHive\|cryptonight\|minero' /var/www/html/

# Remove injected script tags
find /var/www/html -name '*.html' -exec sed -i '/<script.*coinhive/,/<\/script>/d' {} \;

# Check for mining processes running natively
ps aux | grep -iE 'xmrig|xmr-stak|minerd|cpuminer'

# Check for persistence via crontab
crontab -l | grep -i 'mine\|xmr\|crypto'

# Check for unauthorized browser extensions
find /home -path '*Extensions*' -name 'manifest.json' \
  -exec grep -l 'mine\|crypto\|coinhive' {} \;
```

## 5. Recovery
- [ ] Verify mining pool connections have stopped (monitor firewall logs)
- [ ] Confirm CPU usage has returned to normal on affected workstations
- [ ] Re-deploy clean version of compromised website
- [ ] Clear browser caches on affected workstations
- [ ] Remove firewall blocks gradually after monitoring period (except stratum)
- [ ] Verify no residual mining processes are running

## 6. Lessons Learned
- [ ] Document timeline: when was the miner injected vs. when was it detected
- [ ] Calculate resource impact (CPU time, electricity, productivity loss)
- [ ] Identify detection gaps: why was this not caught sooner
- [ ] Review web application security practices
- [ ] Assess need for Content Security Policy (CSP) headers
- [ ] Evaluate browser-based mining detection capabilities

## 7. Prevention Measures
- Deploy Content Security Policy (CSP) headers on all web properties
- Block known mining pool domains and IPs at DNS/firewall
- Block stratum protocol ports (3333, 3334) at perimeter
- Implement Suricata/Snort rules for mining protocol detection
- Deploy browser extensions that block crypto miners (e.g., No Coin, minerBlock)
- Monitor endpoint CPU usage for anomalous sustained spikes
- Regular web application vulnerability scanning
- Implement Subresource Integrity (SRI) for third-party scripts
- Network segmentation to limit mining pool connectivity
- Educate users about cryptojacking signs (slow performance, high CPU)
