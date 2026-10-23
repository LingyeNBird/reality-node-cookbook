#!/usr/bin/env python3
"""Probe a sing-box VLESS+Reality node from the outside — no client credentials needed.

The interesting property of Reality: an unauthenticated TLS handshake is relayed to the
configured handshake target, so a plain client presenting the right SNI receives that
site's **real** certificate. That makes this probe both a camouflage check and the
cheapest health check, and it separates the two common faults:

  * "server closed without sending anything"  -> the node could not reach its target
    (Reality dials the handshake target for every connection, so this kills legit clients too)
  * "certificate does not match the SNI"      -> wrong target, or the target's default
    vhost is answering (common on shared hosting with a mismatched SNI)

Examples
--------
    python node_verify.py --host <SERVER_IP> --sni <SNI>
    python node_verify.py --host <SERVER_IP> --port 443 --sni <SNI> --repeat 3 --json
    python node_verify.py --host <SERVER_IP> --sni <SNI> --expect-subject <SNI>
"""
from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
import time


def probe(host: str, port: int, sni: str, timeout: float, insecure: bool) -> dict:
    """One handshake. Never raises; classifies the failure instead."""
    result: dict = {"ok": False, "kind": "unknown", "detail": ""}

    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    try:
        ctx.set_alpn_protocols(["h2"])
    except NotImplementedError:
        pass
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    started = time.time()
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except ConnectionRefusedError:
        result.update(kind="refused", detail="nothing listening on that port")
        return result
    except socket.timeout:
        result.update(kind="timeout", detail="TCP connect timed out")
        return result
    except OSError as exc:
        result.update(kind="unreachable", detail=f"{type(exc).__name__}: {exc}")
        return result

    try:
        with ctx.wrap_socket(raw, server_hostname=sni) as tls:
            cert = tls.getpeercert() or {}
            result.update(
                ok=True,
                kind="handshake",
                version=tls.version(),
                alpn=tls.selected_alpn_protocol(),
                cipher=(tls.cipher() or [None])[0],
                subject=dict(x[0] for x in cert.get("subject", ())),
                issuer=dict(x[0] for x in cert.get("issuer", ())),
                not_after=cert.get("notAfter"),
                elapsed=round(time.time() - started, 3),
            )
    except ssl.SSLCertVerificationError as exc:
        result.update(kind="cert-mismatch",
                      detail=f"{exc.verify_message if hasattr(exc, 'verify_message') else exc}")
    except (ssl.SSLEOFError, ssl.SSLZeroReturnError):
        result.update(kind="relay-dead",
                      detail="server closed the connection without sending TLS data — "
                             "Reality most likely cannot reach its handshake target")
    except ConnectionResetError:
        result.update(kind="reset",
                      detail="connection reset during the handshake (relay failure or "
                             "an interfering middlebox)")
    except socket.timeout:
        result.update(kind="timeout", detail="handshake timed out")
    except ssl.SSLError as exc:
        result.update(kind="tls-error", detail=str(exc))
    finally:
        try:
            raw.close()
        except OSError:
            pass

    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--sni", required=True, help="server_name configured on the node")
    ap.add_argument("--timeout", type=float, default=12)
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--insecure", action="store_true",
                    help="accept a certificate that does not match the SNI")
    ap.add_argument("--expect-subject", default=None,
                    help="require this substring in the certificate subject")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    runs = [probe(args.host, args.port, args.sni, args.timeout, args.insecure)
            for _ in range(args.repeat)]

    ok = sum(1 for r in runs if r["ok"])
    first = runs[0]
    verdict_problems: list[str] = []

    for r in runs:
        if not r["ok"]:
            verdict_problems.append(f"{r['kind']}: {r['detail']}")
        elif r.get("version") != "TLSv1.3":
            verdict_problems.append(f"negotiated {r.get('version')}, expected TLSv1.3")
        elif r.get("alpn") != "h2":
            verdict_problems.append(f"ALPN is {r.get('alpn')}, expected h2")

    if args.expect_subject and first.get("ok"):
        blob = " ".join(str(v) for v in first.get("subject", {}).values())
        if args.expect_subject.lower() not in blob.lower():
            verdict_problems.append(f"certificate subject {blob!r} lacks "
                                    f"{args.expect_subject!r}")

    if args.json:
        print(json.dumps({"host": args.host, "port": args.port, "sni": args.sni,
                          "runs": runs, "ok": ok, "problems": verdict_problems}, indent=2))
    else:
        print(f"target {args.host}:{args.port}  sni={args.sni}  runs={args.repeat}")
        for i, r in enumerate(runs, 1):
            if r["ok"]:
                print(f"  #{i} TLS {r['version']}  alpn={r['alpn']}  {r['elapsed']}s  "
                      f"subject={r['subject'].get('commonName') or r['subject']}  "
                      f"issuer={r['issuer'].get('organizationName') or r['issuer']}")
            else:
                print(f"  #{i} FAIL {r['kind']}: {r['detail']}")
        print(f"\n{ok}/{len(runs)} handshakes completed")
        if verdict_problems:
            print("problems:")
            for p in verdict_problems:
                print(f"  - {p}")
            print("\nIf the server closed without data, run on the node:")
            print("  journalctl -u <unit> -n 40 | grep -i 'failed to dial dest'")
        else:
            print("OK: the node relays unauthenticated handshakes and presents the "
                  "target's real certificate.")

    return 0 if (ok == len(runs) and not verdict_problems) else 1


if __name__ == "__main__":
    sys.exit(main())
