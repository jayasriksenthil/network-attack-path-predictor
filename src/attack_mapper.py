
import re

TECH = {
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1189": ("Drive-by Compromise", "Initial Access"),
    "T1566": ("Phishing", "Initial Access"),
    "T1557": ("Adversary-in-the-Middle", "Credential Access"),
    "T1592": ("Gather Victim Host Information", "Reconnaissance"),
    "T1595": ("Active Scanning", "Reconnaissance"),
}

OLD_SERVER = re.compile(r"(apache/2\.[0-3]\.|nginx/1\.(?:[0-9]|1[0-7])\.|iis/[5-7]\.|php/[5-7]\.[0-3])", re.I)


def _m(tid, conf, evidence, source):
    return {"technique": tid, "name": TECH[tid][0], "tactic": TECH[tid][1],
            "confidence": conf, "evidence": evidence, "source": source, "type": "observed-exposure"}


def map_indicators(scan):
    http, tls, dns_ = scan.get("http", {}), scan.get("tls", {}), scan.get("dns", {})
    sh = http.get("security_headers", {})
    out = []
    if not http.get("https"):
        out.append(_m("T1557", 0.6, ["Site not served over HTTPS"], "http"))
    if tls.get("available") and tls.get("cert_valid") is False:
        out.append(_m("T1557", 0.55, [f"TLS certificate invalid: {tls.get('error','')[:80]}"], "tls"))
    if tls.get("days_to_expiry") is not None and tls["days_to_expiry"] < 14:
        out.append(_m("T1557", 0.3, [f"Certificate expires in {tls['days_to_expiry']} days"], "tls"))
    if http.get("https") and sh and not sh.get("strict_transport_security"):
        out.append(_m("T1557", 0.35, ["HSTS header missing"], "http"))
    if sh and not sh.get("content_security_policy"):
        out.append(_m("T1189", 0.3, ["Content-Security-Policy header missing"], "http"))
    banner = " ".join(filter(None, [http.get("server"), http.get("x_powered_by")]))
    if banner:
        out.append(_m("T1592", 0.4, [f"Server software disclosed: {banner}"], "http"))
        if OLD_SERVER.search(banner):
            out.append(_m("T1190", 0.5, [f"Potentially outdated software: {banner} (verify against CVE data)"], "http"))
    txt = " ".join(dns_.get("TXT", []))
    if dns_ and "v=spf1" not in txt:
        out.append(_m("T1566", 0.35, ["No SPF record found"], "dns"))
    if dns_ and not dns_.get("DMARC"):
        out.append(_m("T1566", 0.4, ["No DMARC record found"], "dns"))
    merged = {}
    for m in out:
        k = m["technique"]
        if k in merged:
            merged[k]["evidence"] += m["evidence"]
            merged[k]["confidence"] = round(min(0.9, max(merged[k]["confidence"], m["confidence"]) + 0.05), 2)
        else:
            merged[k] = m
    return list(merged.values())
