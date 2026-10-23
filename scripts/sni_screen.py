#!/usr/bin/env python3
"""Screen candidate domains for use as a VLESS+Reality `server_name` / handshake target.

A usable target must:

  * speak TLS 1.3 with X25519 and ALPN h2, and present a valid chain for its own name;
  * not be behind Cloudflare, and preferably not behind any CDN/WAF at all —
    a plain origin (shared hosting, small VPS, regional ISP) is the best camouflage;
  * be reachable from the node itself (this script cannot know that — run
    sni_check_on_host.sh on the node afterwards; that check is the decisive one).

Two traps this script exists to avoid:

  * A local proxy in fake-ip mode poisons plain DNS: every lookup returns the fake
    range (198.18.0.0/15 and friends), so an "is it Cloudflare" test passes everything.
    Here the name is resolved over DoH and the probe connects to the resolved IP with
    an explicit SNI, so the local resolver is never consulted.
  * Cloudflare's published range list is not exhaustive; some proxied space sits
    outside it. The ASN holder is cross-checked as well.

Examples
--------
    python sni_screen.py example.org example.net
    python sni_screen.py --file candidates.txt --workers 12
    python sni_screen.py --file candidates.txt --json
"""
from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request

UA = {"User-Agent": "Mozilla/5.0 (compatible; sni-screen/1.0)"}

# Cloudflare's published ranges. Refreshed from cloudflare.com/ips-v4 when reachable;
# these are the fallback. Deliberately not trusted alone — see ASN check below.
CF_IPV4_FALLBACK = """
173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18
108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17
162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22
"""
CF_IPV6_FALLBACK = """
2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32 2405:8100::/32
2a06:98c0::/29 2c0f:f248::/32
"""

# Holder substrings that mean "do not use this as a target": a shared TLS edge breaks
# the certificate relationship and its addresses are commonly blocklisted.
CDN_WAF = ("cloudflare", "cloudflarespectrum", "fastly", "incapsula", "imperva",
           "sucuri", "cloudfront", "stackpath", "bunny", "azion", "akamai")

# Plain hosting / cloud / PaaS: usable as an origin. Worth a note (their address space
# is heavily used, so it is more likely to be filtered somewhere) but not a rejection.
CLOUD_PAAS = ("amazon", "google", "microsoft", "azure", "digitalocean", "linode",
              "akamai connected cloud", "vultr", "hetzner", "ovh", "shopify",
              "squarespace", "wix", "netlify", "vercel", "render", "heroku")


def http_json(url: str, timeout: float = 15) -> dict:
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def cloudflare_networks() -> list:
    nets = []
    try:
        req = urllib.request.Request("https://www.cloudflare.com/ips-v4", headers=UA)
        raw = urllib.request.urlopen(req, timeout=15).read().decode()
        nets += [ipaddress.ip_network(line.strip()) for line in raw.splitlines() if line.strip()]
    except Exception:
        nets += [ipaddress.ip_network(t) for t in CF_IPV4_FALLBACK.split()]
    nets += [ipaddress.ip_network(t) for t in CF_IPV6_FALLBACK.split()]
    return nets


def resolve_doh(domain: str, doh: str, rtype: str = "A") -> list[str]:
    """Resolve over DoH. Raises on transport failure, returns [] when there is no record.

    Public DoH endpoints occasionally answer 429/5xx; a single miss should not take a
    candidate out of the sweep, so retry briefly before giving up.
    """
    url = f"{doh}?name={urllib.parse.quote(domain)}&type={rtype}"
    last: Exception | None = None
    for attempt in range(3):
        try:
            data = http_json(url)
            return [a["data"] for a in data.get("Answer", []) if a.get("type") in (1, 28)]
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(0.8 * (attempt + 1))
    raise last  # type: ignore[misc]


def asn_holder(ip: str) -> str:
    """Return 'AS<num> <holder>' or '?' when lookups fail."""
    try:
        data = http_json(f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}")["data"]
        asn = data.get("asns", [{}])[0]
        return f"AS{asn.get('asn')} {asn.get('holder', '?')}"
    except Exception:
        pass
    try:
        return http_json(f"https://ipinfo.io/{ip}/json").get("org", "?")
    except Exception:
        return "?"


def classify(holder: str) -> str:
    """Cloud is checked first so 'Akamai Connected Cloud' (Linode) is not read as a CDN."""
    low = holder.lower()
    if any(k in low for k in CLOUD_PAAS):
        return "cloud/paas"
    if any(k in low for k in CDN_WAF):
        return "cdn/waf"
    return "origin"


def tls_probe(ip: str, domain: str, timeout: float) -> dict:
    """Handshake against the resolved IP while presenting the domain as SNI."""
    cmd = ["openssl", "s_client", "-connect", f"{ip}:443", "-servername", domain,
           "-tls1_3", "-groups", "X25519", "-alpn", "h2"]
    try:
        proc = subprocess.run(cmd, input=b"", capture_output=True, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - report, do not crash the sweep
        return {"error": f"{type(exc).__name__}"}
    text = (proc.stderr + proc.stdout).decode(errors="replace")
    # openssl prints "Protocol: TLSv1.3" from the *requested* version even when the
    # handshake dies, so success must be judged by bytes actually read.
    m = re.search(r"SSL handshake has read (\d+) bytes", text)
    read_bytes = int(m.group(1)) if m else 0
    out = {"tls13": False, "alpn": None, "verify": None, "subject": None,
           "read_bytes": read_bytes}
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("ALPN protocol:"):
            out["alpn"] = s.split(":", 1)[1].strip()
        elif s.startswith("Verify return code:"):
            out["verify"] = s.split(":", 1)[1].strip()
        elif s.startswith("subject="):
            out["subject"] = s.split("subject=", 1)[1].strip()
    out["tls13"] = read_bytes > 0 and "TLSv1.3" in text
    if read_bytes == 0 or not out["subject"]:
        reason = "handshake failed (0 bytes read)"
        low = text.lower()
        for needle, label in (("unexpected eof", "server closed without TLS data"),
                              ("connection reset", "connection reset"),
                              ("errno=", "socket write failed"),
                              ("no peer certificate", "no certificate returned")):
            if needle in low:
                reason = label
                break
        out["error"] = reason
    return out


def screen(domain: str, cf_nets: list, doh: str, timeout: float, check_asn: bool,
           strict_cloud: bool) -> dict:
    row = {"domain": domain, "ips": [], "verdict": "fail", "reasons": [], "notes": [],
           "holder": "", "tls": {}}
    try:
        ips = resolve_doh(domain, doh, "A")
        if not ips:
            ips = resolve_doh(domain, doh, "AAAA")
    except Exception as exc:  # noqa: BLE001
        row["reasons"].append(f"doh-failed:{type(exc).__name__}")
        return row
    if not ips:
        row["reasons"].append("no A/AAAA record")
        return row
    row["ips"] = ips

    for ip in ips:
        if any(ipaddress.ip_address(ip) in net for net in cf_nets):
            row["reason_cf"] = True
            row["reasons"].append(f"cloudflare-range {ip}")
            return row

    if check_asn:
        holders = [asn_holder(ip) for ip in ips[:2]]
        row["holder"] = "; ".join(holders)
        kinds = {classify(h) for h in holders}
        if "cdn/waf" in kinds:
            row["reasons"].append("behind a CDN/WAF")
            return row
        if "cloud/paas" in kinds:
            if strict_cloud:
                row["reasons"].append("on a cloud/PaaS platform (--strict)")
                return row
            row["notes"].append("on a cloud/PaaS platform")

    probe = tls_probe(ips[0], domain, timeout)
    row["tls"] = probe
    if "error" in probe:
        row["reasons"].append(probe["error"])
        return row
    if not probe["tls13"]:
        row["reasons"].append("no TLS 1.3")
    if probe["alpn"] != "h2":
        row["reasons"].append(f"alpn={probe['alpn']} (need h2)")
    if not (probe["verify"] or "").startswith("0"):
        row["reasons"].append(f"certificate verify={probe['verify']}")
    if not row["reasons"]:
        row["verdict"] = "pass"
    return row


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("domains", nargs="*")
    ap.add_argument("--file", help="one domain per line, # comments allowed")
    ap.add_argument("--doh", default="https://dns.google/resolve")
    ap.add_argument("--workers", type=int, default=10)
    ap.add_argument("--timeout", type=float, default=25)
    ap.add_argument("--no-asn", action="store_true", help="skip the ASN/host classification")
    ap.add_argument("--strict", action="store_true",
                    help="also reject targets hosted on cloud/PaaS providers")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    domains = list(args.domains)
    if args.file:
        for line in open(args.file, encoding="utf-8"):
            line = line.split("#", 1)[0].strip()
            if line:
                domains.append(line)
    domains = list(dict.fromkeys(d.strip().lower() for d in domains if d.strip()))
    if not domains:
        ap.error("no domains given")

    cf = cloudflare_networks()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        rows = list(pool.map(
            lambda d: screen(d, cf, args.doh, args.timeout, not args.no_asn, args.strict),
            domains))

    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        print(f"{'domain':34} {'verdict':6} {'tls13':6} {'alpn':5} owner / reason")
        for r in rows:
            tls = r.get("tls") or {}
            detail = "; ".join(r["reasons"] + [f"note: {n}" for n in r.get("notes", [])])
            print(f"{r['domain']:34} {r['verdict']:6} {str(tls.get('tls13')):6} "
                  f"{str(tls.get('alpn')):5} {r['holder'] or '-':30} {detail}")
        passing = [r["domain"] for r in rows if r["verdict"] == "pass"]
        print(f"\n{len(passing)}/{len(rows)} passed local screening.")
        if passing:
            print("Next: verify these FROM THE NODE (the decisive check):")
            print("  bash sni_check_on_host.sh " + " ".join(passing))
    return 0 if any(r["verdict"] == "pass" for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
