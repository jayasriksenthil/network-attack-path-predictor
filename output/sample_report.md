# Security Assessment: demo.test

**Risk:** Medium (44/100)
**Prediction model:** LSTM (2 layers, 128 hidden units), trained on 835 ordered attack paths from 34 real intrusions (MITRE CTID Attack Flow corpus)

## 1. Observed evidence (website scan and network traffic)
- **T1557 Adversary-in-the-Middle** (confidence 0.35): HSTS header missing
- **T1189 Drive-by Compromise** (confidence 0.3): Content-Security-Policy header missing
- **T1592 Gather Victim Host Information** (confidence 0.4): Server software disclosed: Apache/2.2.15
- **T1190 Exploit Public-Facing Application** (confidence 0.5): Potentially outdated software: Apache/2.2.15 (verify against CVE data)
- **T1566 Phishing** (confidence 0.45): No SPF record found; No DMARC record found

## 2. LSTM forecast: techniques likely to follow (predicted, not confirmed)
| Rank | Technique | LSTM probability |
|---|---|---|
| 1 | T1203 Exploitation for Client Execution | 0.50 |
| 2 | T1078 Valid Accounts | 0.19 |
| 3 | T1053 Scheduled Task/Job | 0.03 |
| 4 | T1590 Gather Victim Network Information | 0.03 |
| 5 | T1036 Masquerading | 0.03 |

## 3. Most likely attack path (LSTM step-by-step forecast)

T1203 Exploitation for Client Execution -> T1070 Indicator Removal -> T1105 Ingress Tool Transfer -> T1068 Exploitation for Privilege Escalation

Each step is the model's top choice given the observed exposures plus the earlier forecast steps.

## 4. Recommended defensive actions

**Fix what was observed:**
- Serve the site over HTTPS only, enable HSTS, and keep certificates valid.
- Add a Content-Security-Policy header.
- Hide server/version banners (Server, X-Powered-By).
- Update outdated server software and verify it against CVE data. Put a WAF in front of public apps.
- Add SPF and DMARC records for the domain.

**Prepare for what the LSTM predicts:**
- T1203 Exploitation for Client Execution: Patch client software promptly; enable exploit-protection features.
- T1078 Valid Accounts: Enforce MFA, remove unused accounts, alert on unusual logins.
- T1053 Scheduled Task/Job: Audit scheduled tasks/cron jobs; restrict who can create them.
- T1590 Gather Victim Network Information: Reduce publicly exposed network information.
- T1036 Masquerading: Use application allow-listing and monitor renamed or odd-path binaries.

## 5. Confidence and limitations
- On intrusions never seen in training: correct technique in top-3 about 20% of the time, top-5 about 25% (see output/evaluation_results.txt).
- Observed items are weaknesses seen in the scan. They do not prove any attack happened.
- Predicted items are statistical associations learned from historical intrusions.
- The training set is small (34 intrusions), so treat rankings as hints for prioritising defences.