# Scenario 6: Dark Web Monitoring

## Tier: 3 (Demo Only)

## Overview
SOC team monitors dark web forums and marketplaces for company data leaks, stolen credentials, and threat intelligence related to the organization.

## Why Demo Only
- Whonix/Tor network access not practical in Docker containers
- Dark web scraping requires specialized infrastructure
- Legal and ethical considerations for accessing dark web
- Requires persistent monitoring infrastructure

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Resource Development | Acquire Infrastructure: Domains | T1583.001 |
| Reconnaissance | Search Open Websites/Domains | T1593 |
| Reconnaissance | Gather Victim Identity Info | T1589 |
| Resource Development | Search Open Technical Databases | T1597 |

## Monitoring Targets

### Dark Web Forums
- Credential dumps mentioning company domain
- Employee PII listed for sale
- Company intellectual property
- Planned attacks against the organization

### Marketplaces
- Stolen data listings from company breaches
- Access credentials for sale (VPN, RDP, email)
- Exploit kits targeting company technology stack
- Insider threat advertisements

### Paste Sites
- Leaked credentials on Pastebin-like services
- Configuration files or API keys
- Source code leaks
- Internal document dumps

## Detection Indicators
- Company email addresses in credential dumps
- Company domain mentioned in attack planning
- Internal IP ranges or network diagrams shared
- Customer data appearing in breach databases

## Sample Logs
Pre-generated logs in `logs/sample_logs/` simulate dark web monitoring alerts.

## SOC Response
See `respond/playbook.md` for response procedures when company data is found on the dark web.

## Tools for Further Study
- **Have I Been Pwned API**: Check email breach exposure
- **Shodan**: Internet-facing asset discovery
- **SpiderFoot**: OSINT automation framework
- **TheHarvester**: Email and subdomain harvesting
- **Maltego**: Link analysis and data mining
