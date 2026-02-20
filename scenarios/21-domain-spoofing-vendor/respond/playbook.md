# Incident Response Playbook: Domain Spoofing Vendor

## Scenario Overview

An attacker registered a lookalike domain (`g1obalparts-supply.test`) resembling
a legitimate vendor (`globalparts-supply.test`) used by AcmeCorp. The attacker sent
fraudulent invoices with updated bank details, attempting to redirect payments to
an attacker-controlled bank account.

## Severity: CRITICAL (Financial Impact)

## MITRE ATT&CK References

- **T1583.001** - Acquire Infrastructure: Domains
- **T1036** - Masquerading
- **T1566.002** - Phishing: Spearphishing Link
- **T1565** - Data Manipulation (payment redirect)

---

## Phase 1: Detection & Triage

### Indicators of Compromise (IOCs)

| IOC Type         | Value                              | Context                         |
|------------------|------------------------------------|---------------------------------|
| Domain           | `g1obalparts-supply.test`         | Spoofed vendor domain           |
| IP Address       | `203.0.113.50`                    | Attacker mail/web server        |
| Email sender     | `accounts@g1obalparts-supply.test`| Spoofed vendor contact          |
| Email sender     | `j.martinez@g1obalparts-supply.test` | Spoofed vendor manager       |
| Bank (routing)   | `091000019`                       | Attacker bank routing number    |
| Bank (account)   | `****8912`                        | Attacker bank account           |
| Bank name        | `Offshore Trust Bank`             | Fraudulent destination bank     |

### Initial Triage Steps

1. **Confirm the alert** - Verify emails received from `*@g1obalparts-supply.test`
2. **Check email gateway logs** - Look for SPF/DKIM/DMARC failures from vendor-lookalike domains
3. **Review payment queue** - Check if any invoices referencing the spoofed vendor are pending or already processed
4. **Contact finance team** - Determine if any payments have been made using the updated bank details
5. **Compare bank details** - Cross-reference bank details in the suspicious invoice with vendor master records
6. **Check domain registration** - Verify registration date of `g1obalparts-supply.test` (likely very recent)

---

## Phase 2: Containment

### Immediate Actions (first 30 minutes)

- [ ] **DNS Sinkhole**: Redirect `g1obalparts-supply.test` to `0.0.0.0`
- [ ] **Firewall Block**: Block all traffic to/from `203.0.113.50`
- [ ] **Email Gateway Block**: Reject all emails from `*@g1obalparts-supply.test`
- [ ] **Freeze Payments**: Halt all pending payments referencing the spoofed vendor
- [ ] **Finance Alert**: Notify CFO and AP team via phone (not email) about the fraud
- [ ] **Quarantine Emails**: Remove all emails from `*@g1obalparts-supply.test` from mailboxes

### If Payment Was Already Sent

- [ ] **Bank Recall**: Contact company bank immediately to initiate wire recall
- [ ] **FBI IC3 Report**: File a complaint at ic3.gov (Business Email Compromise)
- [ ] **Preserve Evidence**: Save all email headers, DNS logs, and payment records
- [ ] **Legal Notification**: Engage legal counsel and insurance (cyber policy)

### Containment Script

```bash
cd respond/
python containment.py --mode simulate   # Review actions first
python containment.py --mode execute    # Execute containment
```

---

## Phase 3: Eradication

### Actions

1. **Domain takedown** - File abuse report with registrar for `g1obalparts-supply.test`
2. **Verify vendor contacts** - Call the legitimate vendor using known phone numbers (not from the email)
3. **Audit all vendor payments** - Review last 90 days of payments to this vendor for anomalies
4. **Verify no account compromise** - Confirm no finance user accounts were phished alongside the invoice fraud
5. **Update vendor master records** - Ensure all vendor bank details on file are verified through out-of-band channels
6. **Scan attachments** - Analyze the PDF invoice attachments for embedded malware

---

## Phase 4: Recovery

### Steps

1. **Restore payment processes** - Resume normal vendor payments only after:
   - Bank details verified directly with vendor via phone
   - New verification procedure in place for bank detail changes
2. **Implement payment controls**:
   - Require dual-approval for all bank detail changes
   - Require callback verification for any wire transfer > $10,000
   - Flag payments to new bank accounts for manual review
3. **Enhanced email filtering**:
   - Enable vendor domain monitoring (alerts on lookalike domains)
   - Enforce DMARC strict policy for known vendor domains
   - Flag emails from domains < 30 days old
4. **User awareness** - Brief all finance team on vendor impersonation tactics

---

## Phase 5: Lessons Learned

### Post-Incident Review

- [ ] Conduct post-incident review within 5 business days
- [ ] Document the full timeline (from domain registration to detection)
- [ ] Calculate financial impact (amount sent vs. amount recovered)
- [ ] Identify why the fraudulent invoice passed the approval chain
- [ ] Evaluate effectiveness of email authentication (SPF/DKIM/DMARC)
- [ ] Assess the vendor verification process

### Recommended Improvements

| Area                   | Recommendation                                                        |
|------------------------|-----------------------------------------------------------------------|
| Payment Controls       | Mandatory callback to verified vendor phone for bank detail changes   |
| Email Security         | Deploy lookalike domain detection at email gateway                    |
| Vendor Management      | Maintain verified vendor contact registry (not from email signatures) |
| Domain Monitoring      | Subscribe to lookalike domain monitoring for all critical vendors     |
| Training               | Quarterly BEC awareness training for finance and procurement teams    |
| DMARC Enforcement      | Publish DMARC records with `p=reject` for company domain             |
| Invoice Verification   | Require PO matching and three-way match for all invoice payments      |
| New Account Holding    | 48-hour hold on payments to newly added beneficiary accounts          |

---

## Escalation Contacts

| Role                    | Contact Method                |
|-------------------------|-------------------------------|
| SOC Manager             | SOC internal channel          |
| CFO                     | Direct phone line             |
| Accounts Payable Lead   | Direct phone line             |
| Legal / Compliance      | Legal hotline                 |
| Company Bank Contact    | Dedicated banking line        |
| FBI IC3                 | https://ic3.gov               |
| Cyber Insurance Carrier | Policy hotline                |

---

## Automation

The `containment.py` script automates the following actions:
1. DNS sinkhole for spoofed vendor domain
2. Firewall and email gateway blocking
3. Finance team alerting and payment freeze
4. Email quarantine
5. Vendor notification and bank recall initiation

Run with `--mode simulate` first to review, then `--mode execute` against live infrastructure.
