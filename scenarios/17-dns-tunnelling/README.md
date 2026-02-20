# Scenario 17: DNS Tunnelling

## Overview
Simulate a DNS tunnelling attack where an attacker exfiltrates data by encoding it into DNS query subdomains. A compromised workstation sends base32-encoded file chunks as TXT/CNAME queries to an attacker-controlled authoritative DNS server, bypassing traditional network controls that allow DNS traffic.

## Tier
**Tier 1** - Core detection scenario

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Command and Control | Application Layer Protocol: DNS | T1071.004 |
| Exfiltration | Exfiltration Over Alternative Protocol | T1048 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 |

## Attack Flow

```
1. Staging            -> Attacker sets up authoritative DNS server for exfil.test
2. File Preparation   -> Target file is read and split into chunks
3. Base32 Encoding    -> Each chunk is base32-encoded for DNS-safe transport
4. DNS Query Exfil    -> Encoded chunks sent as subdomains: <data>.t.exfil.test
5. Reassembly         -> C2 DNS server decodes subdomains and reassembles file
```

## Components

### DNS Tunnel Client (`attack/simulate_attack.py`)
- Reads a target file and splits it into DNS-safe chunks
- Base32-encodes each chunk into subdomain labels
- Sends TXT and CNAME queries with encoded data to `t.exfil.test`
- Simulates realistic timing and query patterns
- Generates detection logs for the SOC stack

### DNS Tunnel Server (`attack/dns_server.py`)
- Simple authoritative DNS server using dnslib
- Receives queries for `*.t.exfil.test`
- Decodes base32 subdomains and reassembles exfiltrated data
- Acts as the C2 receiver endpoint

### CoreDNS Configuration (`config/Corefile`)
- Forwards all queries to upstream resolver (8.8.8.8)
- Logs all DNS queries for monitoring and detection

### Detection Rules
- **Suricata**: `config/suricata-rules.rules` - Long DNS queries, high-entropy subdomains, TXT query floods
- **Wazuh**: `config/wazuh-rules.xml` - DNS anomaly correlation rules (rule IDs 100500+)

### Verification (`detect/verify_detection.py`)
- Checks Suricata alerts for DNS tunnelling signatures
- Validates Wazuh alert generation for DNS anomalies
- Reports detection coverage against expected alerts

### Response
- **Containment**: `respond/containment.py` - DNS sinkhole and domain blocking
- **Playbook**: `respond/playbook.md` - Full IR procedure for DNS tunnelling incidents

## How to Run

```bash
# 1. (Optional) Start the C2 DNS server in a separate terminal
python3 attack/dns_server.py

# 2. Run the DNS tunnelling attack simulation
python3 attack/simulate_attack.py

# 3. Verify detection
python3 detect/verify_detection.py

# 4. Run containment response
python3 respond/containment.py

# 5. Review response playbook
cat respond/playbook.md
```

## Prerequisites
- Python 3.10+
- Install dependencies: `pip install -r attack/requirements.txt`
- SOC stack running (`soc-stack/scripts/start-core.sh`) or standalone mode (generates local log files)

## Key Indicators of Compromise
- DNS queries with unusually long subdomains (>50 characters)
- High volume of TXT/CNAME queries to a single domain
- Base32/Base64 patterns in subdomain labels
- DNS query rate exceeding normal thresholds (>100 queries/minute to one domain)
- Queries to uncommon or newly registered domains

## Expected Alerts
- Suricata SID 9170001-9170004: DNS tunnelling patterns
- Wazuh Rule 100500-100504: DNS anomaly correlation
