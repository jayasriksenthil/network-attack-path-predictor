
import json, os
from .attack_names import name

MITIGATIONS = {
    "T1059": "Restrict and log script interpreters (PowerShell/shell); enable script-block logging.",
    "T1203": "Patch client software promptly; enable exploit-protection features.",
    "T1204": "User-awareness training and attachment/link sandboxing.",
    "T1078": "Enforce MFA, remove unused accounts, alert on unusual logins.",
    "T1105": "Restrict outbound traffic (egress filtering) and monitor tool downloads.",
    "T1505": "Monitor web directories for new files (file-integrity monitoring); review web-server modules.",
    "T1190": "Patch internet-facing software; place a WAF in front of public apps.",
    "T1566": "Publish SPF, DKIM and DMARC; filter email attachments.",
    "T1053": "Audit scheduled tasks/cron jobs; restrict who can create them.",
    "T1036": "Use application allow-listing and monitor renamed or odd-path binaries.",
    "T1082": "Limit discovery commands for normal users; alert on bursts of discovery activity.",
    "T1068": "Keep OS patched; limit local privileges.",
    "T1199": "Review third-party access and trust relationships.",
    "T1074": "Monitor unusual data staging folders and large archive creation.",
    "T1590": "Reduce publicly exposed network information.",
    "T1486": "Keep offline, regularly tested backups; restrict write access to file shares; alert on mass file changes.",
    "T1070": "Forward logs to a central, tamper-resistant store so attackers cannot erase their traces.",
    "T1071": "Monitor outbound traffic for beaconing and restrict which hosts can reach the internet.",
    "T1041": "Restrict and monitor outbound data transfers (egress filtering, data-loss prevention).",
}
OBSERVED_FIX = {
    "T1557": "Serve the site over HTTPS only, enable HSTS, and keep certificates valid.",
    "T1189": "Add a Content-Security-Policy header.",
    "T1592": "Hide server/version banners (Server, X-Powered-By).",
    "T1566": "Add SPF and DMARC records for the domain.",
    "T1190": "Update outdated server software and verify it against CVE data. Put a WAF in front of public apps.",
    "T1498": "Use DDoS protection (CDN or scrubbing service), rate limiting and connection limits on public services.",
    "T1110": "Enable account lockout and MFA, rate-limit login attempts, and alert on repeated failures.",
    "T1595": "Rate-limit and alert on scanning, close unused ports, and block repeat scanners at the firewall.",
    "T1071": "Monitor outbound traffic for beaconing and restrict which hosts can reach the internet.",
}
MODEL_INFO = {
    "name": "LSTM (2 layers, 128 hidden units)",
    "training_data": "835 ordered attack paths from 34 real intrusions (MITRE CTID Attack Flow corpus)",
    "evaluation": "On intrusions never seen in training: correct technique in top-3 about 20% of the time, top-5 about 25% (see output/evaluation_results.txt)",
}

PROMPT = """You are a defensive security analyst. Using ONLY the structured evidence below, write a concise report with sections:
Summary, Observed findings, LSTM forecast, Recommended defensive actions, Confidence and limitations.
Rules: label items as Observed / Predicted; never claim an attack occurred; the forecast comes from an LSTM trained on MITRE Attack Flow
sequences and is a statistical association, not confirmed activity. Mention the model's measured accuracy in the limitations.

{payload}"""


def _tid(t): return f"{t} {name(t)}"


def template_report(p):
    L = [f"# Security Assessment: {p['domain']}", "",
         f"**Risk:** {p['risk']['level']} ({p['risk']['score']}/100)",
         f"**Prediction model:** {p['model']['name']}, trained on {p['model']['training_data']}", "",
         "## 1. Observed evidence (website scan and network traffic)"]
    for m in p["mappings"]:
        tag = " [network traffic]" if m.get("source") == "network-flow" else ""
        L.append(f"- **{_tid(m['technique'])}**{tag} (confidence {m['confidence']}): " + "; ".join(m["evidence"]))
    if not p["mappings"]: L.append("- No exposures found by the passive checks.")
    L += ["", "## 2. LSTM forecast: techniques likely to follow (predicted, not confirmed)",
          "| Rank | Technique | LSTM probability |", "|---|---|---|"]
    for i, q in enumerate(p["predictions"], 1):
        L.append(f"| {i} | {_tid(q['technique'])} | {q['score']:.2f} |")
    if p.get("path"):
        L += ["", "## 3. Most likely attack path (LSTM step-by-step forecast)", "",
              " -> ".join(_tid(x["technique"]) for x in p["path"]),
              "", "Each step is the model's top choice given the observed exposures plus the earlier forecast steps."]
    L += ["", "## 4. Recommended defensive actions", "", "**Fix what was observed:**"]
    for t in dict.fromkeys(m["technique"] for m in p["mappings"]):
        if t in OBSERVED_FIX: L.append(f"- {OBSERVED_FIX[t]}")
    L += ["", "**Prepare for what the LSTM predicts:**"]
    for q in p["predictions"]:
        L.append(f"- {_tid(q['technique'])}: {MITIGATIONS.get(q['technique'], 'Add detection and logging coverage for this technique.')}")
    L += ["", "## 5. Confidence and limitations",
          f"- {p['model']['evaluation']}.",
          "- Observed items are weaknesses seen in the scan. They do not prove any attack happened.",
          "- Predicted items are statistical associations learned from historical intrusions.",
          "- The training set is small (34 intrusions), so treat rankings as hints for prioritising defences."]
    return "\n".join(L)


def ai_report(payload):
    key = os.getenv("ANTHROPIC_API_KEY")
    if not key:
        return template_report(payload)
    import anthropic
    slim = {k: payload[k] for k in ("domain", "mappings", "predictions", "path", "risk", "model")}
    for q in slim["predictions"] + slim["path"]: q["name"] = name(q["technique"])
    client = anthropic.Anthropic(api_key=key)
    msg = client.messages.create(model="claude-sonnet-5-5", max_tokens=1800,
                                 messages=[{"role": "user", "content": PROMPT.format(payload=json.dumps(slim, indent=2))}])
    return msg.content[0].text
