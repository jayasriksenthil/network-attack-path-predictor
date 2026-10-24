import json, socket, ssl, sys
from datetime import datetime, timezone
import requests

try:
    import dns.resolver
except ImportError:
    dns = None

SECURITY_HEADERS = {
    "content_security_policy": "content-security-policy",
    "strict_transport_security": "strict-transport-security",
    "x_frame_options": "x-frame-options",
    "x_content_type_options": "x-content-type-options",
    "referrer_policy": "referrer-policy",
    "permissions_policy": "permissions-policy",
}


def get_dns(domain):
    out = {}
    if dns is None:
        try:
            out["A"] = sorted({r[4][0] for r in socket.getaddrinfo(domain, None)})
        except socket.gaierror:
            out["A"] = []
        return out
    res = dns.resolver.Resolver()
    res.lifetime = 5
    for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            out[rtype] = [r.to_text() for r in res.resolve(domain, rtype)]
        except Exception:
            out[rtype] = []
    try:
        out["DMARC"] = [r.to_text() for r in res.resolve(f"_dmarc.{domain}", "TXT")]
    except Exception:
        out["DMARC"] = []
    return out


def get_tls(domain, port=443):
    info = {"available": False}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as s:
                cert = s.getpeercert()
                exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                info.update(
                    available=True,
                    protocol=s.version(),
                    issuer=dict(x[0] for x in cert["issuer"]).get("organizationName"),
                    expires=exp.isoformat(),
                    days_to_expiry=(exp - datetime.now(timezone.utc)).days,
                    cert_valid=True,
                )
    except ssl.SSLCertVerificationError as e:
        info.update(available=True, cert_valid=False, error=str(e))
    except Exception as e:
        info["error"] = str(e)
    return info


def get_http(domain):
    info = {"https": False}
    for scheme in ("https", "http"):
        try:
            r = requests.get(f"{scheme}://{domain}", timeout=8, allow_redirects=True,
                             headers={"User-Agent": "DefensiveAssessmentBot/1.0"})
            h = {k.lower(): v for k, v in r.headers.items()}
            info.update(
                https=r.url.startswith("https://"),
                final_url=r.url,
                status_code=r.status_code,
                server=h.get("server"),
                x_powered_by=h.get("x-powered-by"),
                security_headers={k: (v in h) for k, v in SECURITY_HEADERS.items()},
            )
            return info
        except requests.RequestException as e:
            info["error"] = str(e)
    return info


def scan_domain(domain):
    domain = domain.strip().lower().replace("https://", "").replace("http://", "").strip("/")
    return {
        "domain": domain,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "dns": get_dns(domain),
        "tls": get_tls(domain),
        "http": get_http(domain),
    }


if __name__ == "__main__":
    d = sys.argv[1] if len(sys.argv) > 1 else input("Enter domain you are authorized to assess: ")
    print(json.dumps(scan_domain(d), indent=2))
