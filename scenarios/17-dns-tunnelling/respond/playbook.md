# Incident Response Playbook: DNS Tunnelling

## Scenario 17 - DNS Tunnelling Data Exfiltration

### Severity: HIGH
### MITRE ATT&CK: T1071.004 (Application Layer Protocol: DNS), T1048 (Exfiltration Over Alternative Protocol)

---

## 1. Detection
- [ ] Suricata alert: Unusually long DNS queries (>100 characters)
- [ ] Suricata alert: High entropy subdomain labels (base32/base64 patterns)
- [ ] Suricata alert: TXT/CNAME query flood to a single domain
- [ ] Wazuh alert: DNS query anomaly correlation rule triggered
- [ ] DNS server logs show high volume of queries to uncommon domain
- [ ] Network baseline deviation: DNS traffic volume spike

## 2. Triage (First 15 minutes)
- [ ] Confirm the alert is a true positive (not legitimate long DNS queries like CDN/DKIM)
- [ ] Identify the source host generating the tunnel queries
- [ ] Determine the destination domain receiving encoded data
- [ ] Check domain registration: is the domain newly registered or suspicious?
- [ ] Assess data volume: estimate bytes exfiltrated based on query count and subdomain length
- [ ] Check if the source host has known malware or compromise indicators

### Key Questions
- Is the domain used by any legitimate service (e.g., Akamai, Cloudflare)?
- What is the query rate (queries per minute)?
- Are the subdomain labels random/encoded or human-readable?
- Is the query type unusual (TXT, NULL, CNAME for data, not A records)?

## 3. Containment (First 30 minutes)
- [ ] **Immediate**: Apply DNS sinkhole for the exfiltration domain
- [ ] **Immediate**: Block the domain at the DNS resolver/firewall level
- [ ] Restrict DNS traffic to approved resolvers only (force DNS through corporate resolver)
- [ ] Isolate the compromised host from the network
- [ ] If data was exfiltrated: begin data classification of affected files
- [ ] Preserve evidence: DNS query logs, packet captures, host forensics

### Containment Commands
```bash
# DNS sinkhole - add to /etc/hosts on DNS server
echo "0.0.0.0  exfil.test" >> /etc/hosts
echo "0.0.0.0  t.exfil.test" >> /etc/hosts

# Block at firewall - prevent DNS to unauthorized servers
iptables -A OUTPUT -p udp --dport 53 ! -d <APPROVED_DNS_IP> -j DROP
iptables -A OUTPUT -p tcp --dport 53 ! -d <APPROVED_DNS_IP> -j DROP

# Block specific exfil domain at Suricata
# Add to local.rules:
# drop dns any any -> any 53 (msg:"Block DNS tunnel domain"; dns.query; content:"exfil.test"; sid:9999017;)

# Capture DNS traffic for forensics
tcpdump -i any -w /tmp/dns_capture.pcap port 53

# Check for active DNS tunnel processes on compromised host
netstat -anp | grep :53
ps aux | grep -i dns
```

## 4. Eradication
- [ ] Identify and remove the malware/tool performing DNS tunnelling
- [ ] Common tools to look for: iodine, dnscat2, dns2tcp, Cobalt Strike DNS beacon
- [ ] Check for persistence mechanisms (crontab, systemd, startup scripts)
- [ ] Scan host with endpoint detection tool (EDR)
- [ ] Review all outbound DNS queries from the host in the last 30 days
- [ ] Check for lateral movement from the compromised host
- [ ] Reset credentials for any accounts accessed from the compromised host

### Common DNS Tunnel Tools
| Tool | Indicator |
|------|-----------|
| iodine | TXT queries, `t.` prefix domains |
| dnscat2 | CNAME/TXT/MX queries, random subdomains |
| dns2tcp | TXT queries, base64-encoded labels |
| Cobalt Strike | A/AAAA queries, short encoded labels |

## 5. Recovery
- [ ] Rebuild or reimage the compromised host
- [ ] Enforce DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) to approved resolvers only
- [ ] Implement DNS query length monitoring at the resolver level
- [ ] Add the exfiltration domain to permanent blocklists
- [ ] Re-enable network access after verification
- [ ] Monitor for re-infection indicators for 72 hours

## 6. Lessons Learned
- [ ] Document timeline of exfiltration and response
- [ ] Calculate total data volume exfiltrated
- [ ] Identify initial compromise vector (how did the tunnel tool get installed?)
- [ ] Assess if DNS monitoring was adequate before the incident
- [ ] Review DNS resolver configuration for logging gaps
- [ ] Update detection rules based on observed patterns

## 7. Prevention Measures
- Force all DNS through corporate resolvers (block direct DNS to external servers)
- Implement DNS query logging and monitoring at resolver level
- Deploy DNS-specific IDS rules (query length, entropy analysis)
- Use DNS filtering/reputation services (e.g., Cisco Umbrella, Quad9)
- Monitor for anomalous query volumes per host (baseline + threshold)
- Block known DNS tunnelling tool signatures at the endpoint level
- Implement split-horizon DNS to limit internal DNS exposure
- Regular review of DNS query patterns for anomalies
