# Incident Response Playbook: Domain Spoofing & Data Theft

## Scenario Overview

An attacker has registered a lookalike domain (`acmec0rp.local`) that mimics the
company domain (`acmecorp.local`). A phishing site was deployed to harvest employee
credentials. Stolen credentials were used to access internal systems and exfiltrate
sensitive data.

## Severity: HIGH

## MITRE ATT&CK References

- **T1583.001** - Acquire Infrastructure: Domains
- **T1566.002** - Phishing: Spearphishing Link
- **T1071** - Application Layer Protocol
- **T1078** - Valid Accounts
- **T1041** - Exfiltration Over C2 Channel

---

## Phase 1: Detection & Triage

### Indicators of Compromise (IOCs)

| IOC Type       | Value                          | Context                        |
|----------------|--------------------------------|--------------------------------|
| Domain         | `acmec0rp.local`              | Spoofed lookalike domain       |
| Domain         | `acmecorp-login.test`         | Phishing login page            |
| IP Address     | `203.0.113.50`                | Attacker server                |
| URL            | `https://acmecorp-login.test/login` | Credential harvesting page |
| Email sender   | `it-security@acmec0rp.local`  | Phishing email sender          |
| User-Agent     | `HTTrack/3.49`                | Site cloning tool              |

### Initial Triage Steps

1. **Confirm the alert** - Verify DNS queries to `acmec0rp.local` or `acmecorp-login.test` in DNS logs
2. **Identify affected users** - Search email gateway for messages from `*@acmec0rp.local`
3. **Check web proxy logs** - Look for HTTP/HTTPS connections to `acmecorp-login.test` or `203.0.113.50`
4. **Review authentication logs** - Check for logins from `203.0.113.50` (attacker IP)
5. **Assess data exposure** - Identify what files were accessed by compromised accounts

---

## Phase 2: Containment

### Immediate Actions (first 30 minutes)

- [ ] **DNS Sinkhole**: Redirect `acmec0rp.local` and `acmecorp-login.test` to `0.0.0.0`
- [ ] **Firewall Block**: Block all traffic to/from `203.0.113.50` at perimeter firewall
- [ ] **Proxy Block**: Add both domains to web proxy blocklist
- [ ] **Email Quarantine**: Remove all phishing emails matching sender domain `acmec0rp.local`
- [ ] **Session Kill**: Revoke all active sessions for identified compromised users
- [ ] **Credential Reset**: Force password reset for all compromised users

### Short-Term Actions (first 4 hours)

- [ ] Block sender domain `acmec0rp.local` at email gateway
- [ ] Block outbound port 8443 to attacker IP
- [ ] Disable VPN access for compromised accounts pending investigation
- [ ] Preserve forensic evidence (email headers, DNS logs, web proxy logs, auth logs)
- [ ] Notify affected users via out-of-band communication (phone, not email)

### Containment Script

```bash
cd respond/
python containment.py --mode simulate   # Review actions first
python containment.py --mode execute    # Execute containment
```

---

## Phase 3: Eradication

### Actions

1. **Domain takedown** - Submit abuse report to registrar for `acmec0rp.local` and `acmecorp-login.test`
2. **Verify no persistence** - Check that attacker did not install backdoors, create new accounts, or modify configurations
3. **Audit all accessed systems** - Review file access logs for each compromised account
4. **Scan for malware** - Run endpoint detection scans on workstations of compromised users
5. **Review firewall rules** - Ensure no unauthorized rules were added
6. **Check for data staging** - Look for unusual archive files or compressed data on accessed servers

---

## Phase 4: Recovery

### Steps

1. **Re-enable accounts** - After password reset and MFA re-enrollment, re-enable user accounts
2. **Monitor closely** - Set up enhanced monitoring for:
   - DNS queries to lookalike domains (Levenshtein distance < 3 from company domain)
   - Logins from external IPs for previously compromised users
   - Large outbound data transfers
3. **Restore VPN access** - Only after verifying clean endpoints
4. **Validate email gateway** - Confirm DMARC/SPF/DKIM enforcement is strict (p=reject)

---

## Phase 5: Lessons Learned

### Post-Incident Review

- [ ] Conduct post-incident review within 5 business days
- [ ] Document the full timeline of the attack
- [ ] Identify detection gaps - what could have caught this earlier?
- [ ] Evaluate email security controls (SPF, DKIM, DMARC policy)
- [ ] Assess user awareness - did users report the phishing email?
- [ ] Review domain monitoring capabilities

### Recommended Improvements

| Area                   | Recommendation                                                      |
|------------------------|---------------------------------------------------------------------|
| Email Security         | Enforce DMARC `p=reject` for company domain                        |
| Domain Monitoring      | Subscribe to lookalike domain monitoring service                    |
| User Awareness         | Conduct phishing simulation training quarterly                      |
| DNS Security           | Implement DNS sinkholing for known-bad domains in real time         |
| MFA                    | Require phishing-resistant MFA (FIDO2/WebAuthn) for all users       |
| DLP                    | Enable Data Loss Prevention policies for sensitive file transfers    |
| SIEM Rules             | Add correlation rules for phishing email + credential use sequence  |

---

## Escalation Contacts

| Role                    | Contact Method                |
|-------------------------|-------------------------------|
| SOC Manager             | SOC internal channel          |
| IT Security Lead        | Direct phone                  |
| Legal / Privacy         | Legal hotline                 |
| Executive Management    | CISO direct line              |
| External (if needed)    | Incident response retainer    |

---

## Automation

The `containment.py` script automates the following actions:
1. DNS sinkhole for malicious domains
2. Firewall and proxy blocking
3. Credential reset for compromised users
4. Session revocation
5. Email quarantine

Run with `--mode simulate` first to review, then `--mode execute` against live infrastructure.
