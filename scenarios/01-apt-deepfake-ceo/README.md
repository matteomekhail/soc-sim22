# Scenario 1: APT Deepfake CEO Fraud

## Tier: 3 (Demo Only)

## Overview
An advanced persistent threat group uses deepfake technology (AI-generated video/audio) to impersonate the CEO during a video call, convincing the CFO to authorize a fraudulent wire transfer.

## Why Demo Only
- DeepFaceLab and similar tools require dedicated GPU (CUDA/ROCm)
- Real-time deepfake generation needs significant compute resources
- Audio cloning requires extensive sample data
- Video conferencing API integration is complex and platform-specific

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Phishing | T1566 |
| Execution | User Execution | T1204 |
| Resource Development | Obtain Capabilities | T1588 |
| Impact | Financial Theft | T1657 |

## Attack Flow

```
1. Reconnaissance      → Collect CEO video/audio samples from public sources
2. Deepfake Creation   → Train AI model on CEO's face/voice
3. Social Engineering   → Schedule fake "urgent" video call with CFO
4. Impersonation       → Use real-time deepfake during video call
5. Financial Impact    → CFO authorizes wire transfer to attacker account
```

## Detection Indicators

### Email/Communication
- Urgency language in meeting request
- Unusual meeting scheduling pattern (outside normal hours)
- Meeting request from slightly different email domain
- No other attendees in "confidential" meeting

### Financial
- Wire transfer to new/unfamiliar account
- Transfer amount exceeds normal authorization limits
- Request bypasses standard approval workflow
- International transfer to high-risk jurisdiction

### Technical (if deepfake suspected)
- Video quality inconsistencies
- Audio-visual sync issues
- Unnatural facial movements or lighting
- Metadata analysis of video stream

## Sample Logs
Pre-generated logs in `logs/sample_logs/` demonstrate:
- Phishing email requesting urgent video meeting
- Calendar event creation
- VoIP/video call metadata
- Wire transfer authorization events
- Post-incident investigation artifacts

## SOC Response
See `respond/playbook.md` for the full incident response procedure including:
- Callback verification protocol
- Financial transaction freeze procedures
- Digital forensics on video call artifacts
- Law enforcement coordination

## Tools for Further Study
- **DeepFaceLab**: Open-source deepfake creation (requires GPU)
- **Resemblyzer**: Voice similarity analysis
- **FaceForensics++**: Deepfake detection dataset
- **Microsoft Video Authenticator**: Deepfake detection tool
