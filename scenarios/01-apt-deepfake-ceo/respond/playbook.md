# Incident Response Playbook: Deepfake CEO Fraud

## Severity: CRITICAL
## MITRE ATT&CK: T1566, T1204, T1657

---

## 1. Detection
- [ ] Financial team reports suspicious wire transfer request
- [ ] Video call quality/behavior anomalies reported
- [ ] Email domain inconsistency discovered
- [ ] Callback to CEO reveals they didn't make the request

## 2. Immediate Actions (First 15 minutes)
- [ ] **FREEZE** the wire transfer immediately (contact bank)
- [ ] Verify CEO's actual location and activities
- [ ] Preserve all communication records (email, calendar, call logs)
- [ ] Do NOT delete any evidence

## 3. Containment
- [ ] Contact the receiving bank to freeze funds
- [ ] Alert all C-suite about the active fraud attempt
- [ ] Implement mandatory callback verification for all wire transfers
- [ ] Block the spoofed email domain company-wide

## 4. Investigation
- [ ] Analyze email headers for origin
- [ ] Review video call metadata and recordings
- [ ] Check for reconnaissance (CEO's public videos accessed/scraped)
- [ ] Assess if other employees were targeted

## 5. Recovery
- [ ] Recover funds through banking channels
- [ ] Implement dual-authorization for transfers above threshold
- [ ] Deploy deepfake awareness training
- [ ] Update verification procedures for video-based requests

## 6. Prevention
- Mandatory callback verification for financial requests
- Multi-person authorization for large transfers
- Deepfake awareness training for finance team
- Code word protocol for urgent executive requests
- Limit public video/audio content of executives
