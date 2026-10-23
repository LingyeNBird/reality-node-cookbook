#!/usr/bin/env python3
"""End-to-end test of a VLESS+Reality node with a real client core.

Runs a throwaway sing-box client with a local mixed inbound, then compares three links:

    direct         (control — must differ from the node)
    via HTTP proxy
    via SOCKS5h proxy   (both must equal the node's egress address)

A node can pass every TLS-layer probe and still be unusable; this is the check that
proves the credentials, flow and Reality settings actually work together.

Examples
--------
    python client_e2e.py --sing-box ./sing-box --server <IP> --uuid <UUID> \\
        --sni <SNI> --pbk <PUBLIC_KEY> --sid <SHORT_ID>
    python client_e2e.py ... --dry-run        # print the generated client config only

Requires: the sing-box binary, and curl on PATH (for SOCKS5h).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

PROXY_ENV = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
             "http_proxy", "https_proxy", "all_proxy", "no_proxy")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def build_config(args, listen_port: int) -> dict:
    return {
        "log": {"level": "info", "timestamp": True},
        "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1",
                      "listen_port": listen_port}],
        "outbounds": [{
            "type": "vless", "tag": "node",
            "server": args.server, "server_port": args.port,
            "uuid": args.uuid, "flow": args.flow,
            "tls": {
                "enabled": True, "server_name": args.sni,
                "utls": {"enabled": True, "fingerprint": args.fingerprint},
                "reality": {"enabled": True, "public_key": args.pbk,
                            "short_id": args.sid},
            },
        }, {"type": "direct", "tag": "direct"}],
        "route": {"final": "node"},
    }


def clean_env() -> dict:
    env = {k: v for k, v in os.environ.items() if k not in PROXY_ENV}
    return env


def curl(url: str, proxy: str | None, timeout: float) -> str:
    cmd = ["curl", "-sS", "--max-time", str(int(timeout)), "--noproxy", "*"]
    if proxy:
        cmd += ["-x", proxy]
    cmd.append(url)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10,
                          env=clean_env())
    if proc.returncode != 0:
        return f"<error {proc.returncode}: {(proc.stderr or '').strip()[:90]}>"
    return proc.stdout.strip()[:120]


def wait_for_port(port: int, timeout: float = 15) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sing-box", required=True, help="path to a sing-box binary")
    ap.add_argument("--server", required=True)
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--uuid", required=True)
    ap.add_argument("--sni", required=True)
    ap.add_argument("--pbk", required=True, help="Reality public key")
    ap.add_argument("--sid", default="", help="Reality short id (may be empty)")
    ap.add_argument("--flow", default="xtls-rprx-vision")
    ap.add_argument("--fingerprint", default="chrome")
    ap.add_argument("--listen-port", type=int, default=0)
    ap.add_argument("--echo-url", default="https://ipinfo.io/ip")
    ap.add_argument("--timeout", type=float, default=30)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    listen_port = args.listen_port or free_port()
    cfg = build_config(args, listen_port)

    if args.dry_run:
        print(json.dumps(cfg, indent=2))
        return 0

    if not shutil.which("curl"):
        print("error: curl is required (SOCKS5h testing)", file=sys.stderr)
        return 2

    tmpdir = tempfile.mkdtemp(prefix="reality-e2e-")
    cfg_path = os.path.join(tmpdir, "client.json")
    log_path = os.path.join(tmpdir, "client.log")
    with open(cfg_path, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)

    log = open(log_path, "w", encoding="utf-8")
    proc = subprocess.Popen([args.sing_box, "run", "-c", cfg_path],
                            stdout=log, stderr=subprocess.STDOUT, env=clean_env())
    try:
        if not wait_for_port(listen_port):
            print("error: the client never opened its mixed port", file=sys.stderr)
            return 1
        print(f"client listening on 127.0.0.1:{listen_port}\n")

        direct = curl(args.echo_url, None, args.timeout)
        http = curl(args.echo_url, f"http://127.0.0.1:{listen_port}", args.timeout)
        socks = curl(args.echo_url, f"socks5h://127.0.0.1:{listen_port}", args.timeout)

        print(f"  direct (control) : {direct}")
        print(f"  via HTTP proxy   : {http}")
        print(f"  via SOCKS5h      : {socks}")

        good = (http == socks and "<error" not in http and "<error" not in socks
                and direct != http)
        print("\n" + ("PASS: both proxy paths agree and differ from the control."
                      if good else
                      "FAIL: see the client log below."))
        return 0 if good else 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()
        with open(log_path, encoding="utf-8", errors="replace") as fh:
            tail = fh.read().splitlines()[-8:]
        if tail:
            print("\nclient log (tail):")
            for line in tail:
                print("  " + line)


if __name__ == "__main__":
    sys.exit(main())
