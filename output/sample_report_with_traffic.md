# Security Assessment: (network flows only)

**Risk:** High (59/100)
**Prediction model:** LSTM (2 layers, 128 hidden units), trained on 835 ordered attack paths from 34 real intrusions (MITRE CTID Attack Flow corpus)

## 1. Observed evidence (website scan and network traffic)
- **T1498 Network Denial of Service** [network traffic] (confidence 0.95): 199 of 1,500 network flows (13.3%) classified as DoS Hulk (mean probability 0.99, model precision for this type 1.00)
- **T1110 Brute Force** [network traffic] (confidence 0.95): 70 of 1,500 network flows (4.7%) classified as FTP-Patator (mean probability 1.00, model precision for this type 1.00); 79 of 1,500 network flows (5.3%) classified as SSH-Patator (mean probability 0.99, model precision for this type 0.99)
- **T1595 Active Scanning** [network traffic] (confidence 0.95): 251 of 1,500 network flows (16.7%) classified as PortScan (mean probability 1.00, model precision for this type 1.00)

## 2. LSTM forecast: techniques likely to follow (predicted, not confirmed)
| Rank | Technique | LSTM probability |
|---|---|---|
| 1 | T1486 Data Encrypted for Impact | 0.60 |
| 2 | T1105 Ingress Tool Transfer | 0.04 |
| 3 | T1203 Exploitation for Client Execution | 0.04 |
| 4 | T1070 Indicator Removal | 0.03 |
| 5 | T1082 System Information Discovery | 0.03 |

## 3. Most likely attack path (LSTM step-by-step forecast)

T1486 Data Encrypted for Impact -> T1070 Indicator Removal -> T1071 Application Layer Protocol -> T1041 Exfiltration Over C2 Channel

Each step is the model's top choice given the observed exposures plus the earlier forecast steps.

## 4. Recommended defensive actions

**Fix what was observed:**
- Use DDoS protection (CDN or scrubbing service), rate limiting and connection limits on public services.
- Enable account lockout and MFA, rate-limit login attempts, and alert on repeated failures.
- Rate-limit and alert on scanning, close unused ports, and block repeat scanners at the firewall.

**Prepare for what the LSTM predicts:**
- T1486 Data Encrypted for Impact: Keep offline, regularly tested backups; restrict write access to file shares; alert on mass file changes.
- T1105 Ingress Tool Transfer: Restrict outbound traffic (egress filtering) and monitor tool downloads.
- T1203 Exploitation for Client Execution: Patch client software promptly; enable exploit-protection features.
- T1070 Indicator Removal: Forward logs to a central, tamper-resistant store so attackers cannot erase their traces.
- T1082 System Information Discovery: Limit discovery commands for normal users; alert on bursts of discovery activity.

## 5. Confidence and limitations
- On intrusions never seen in training: correct technique in top-3 about 20% of the time, top-5 about 25% (see output/evaluation_results.txt).
- Observed items are weaknesses seen in the scan. They do not prove any attack happened.
- Predicted items are statistical associations learned from historical intrusions.
- The training set is small (34 intrusions), so treat rankings as hints for prioritising defences.