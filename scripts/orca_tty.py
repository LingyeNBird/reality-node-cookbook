#!/usr/bin/env python3
"""Drive an Orca terminal from a script, safely.

The three things this wrapper exists for:

1. Multi-line shell scripts must reach the remote shell without quoting damage.
   `send-script` base64-encodes the file and runs `base64 -d | bash` on the far side.
2. `terminal wait --for tui-idle` is unreliable (commands often finish before the
   wait begins, and the wait then blocks). `wait-quiet` instead watches the read
   cursor stop moving, and `wait-prompt` watches for an expected prompt.
3. **Scope fence.** Terminal listings in a worktree include every other terminal in
   that worktree, and their output is somebody else's business. This tool only ever
   touches handles it created itself: `create` records them in a local allowlist
   (`~/.orca-tty/created.json`), `list` shows nothing else, and every read or write
   against an unknown handle is refused — including the terminal this agent is
   running in. There is deliberately no flag to widen that.

All reads are cursor-based, so output is never replayed.

Examples
--------
    orca_tty.py list
    orca_tty.py create --title "node" --command 'ssh -p <port> -i <key> root@<ip>'
    orca_tty.py wait-prompt --terminal <handle> --pattern ':~#\\s*$'
    orca_tty.py send-script --terminal <handle> --file scripts/node_setup.sh
    orca_tty.py read --terminal <handle>
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import time


class OrcaError(RuntimeError):
    pass


def resolve_cli(override: str | None = None) -> str:
    """Pick the executable once, as the Orca skill requires.

    ORCA_CLI_COMMAND (exported inside Orca-managed WSL sessions) wins. A dev
    checkout exposes orca-dev. On Linux, bare `orca` is the GNOME screen reader
    unless we are inside an Orca terminal, so prefer orca-ide there.
    """
    if override:
        return override
    env = os.environ.get("ORCA_CLI_COMMAND")
    if env:
        return env
    if os.environ.get("ORCA_DEV_REPO_ROOT") and shutil.which("orca-dev"):
        return "orca-dev"
    if sys.platform.startswith("linux"):
        inside = any(k.startswith("ORCA_") for k in os.environ)
        if not inside and shutil.which("orca-ide"):
            return "orca-ide"
    return "orca"


# ------------------------------------------------------------------ scope fence
#
# Orca's terminal listing is worktree-wide: it returns every terminal in the
# worktree, previews included. Reading those is how an agent ends up looking at
# output it was never given. So this tool keeps its own allowlist — handles it
# created — and refuses everything else, with no override flag.

STATE_DIR = pathlib.Path.home() / ".orca-tty"
STATE_FILE = STATE_DIR / "created.json"
MAX_TRACKED = 50


def _load_created() -> dict:
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_created(data: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(STATE_FILE)


def _remember(handle: str, title: str) -> None:
    data = _load_created()
    data[handle] = {"title": title, "created": time.time()}
    if len(data) > MAX_TRACKED:
        data = dict(sorted(data.items(), key=lambda kv: kv[1].get("created", 0))[-MAX_TRACKED:])
    _save_created(data)


def _guard(handle: str) -> None:
    """Hard stop for any handle this tool did not create itself."""
    if handle in _load_created():
        return
    raise OrcaError(
        f"refusing terminal {handle!r}: this tool only touches terminals it created "
        "itself. Every other terminal in this worktree — including the one this agent "
        "is running in — is out of scope. Run `create` and use the handle it prints."
    )


def _run(cli: str, args: list[str]) -> subprocess.CompletedProcess:
    proc = subprocess.run([cli, *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        raise OrcaError(f"{cli} {' '.join(args)} exited {proc.returncode}\n"
                        f"stdout: {proc.stdout[:400]}\nstderr: {proc.stderr[:400]}")
    return proc


def _json(cli: str, args: list[str]) -> dict:
    out = _run(cli, args).stdout
    try:
        payload = json.loads(out)
    except json.JSONDecodeError as exc:
        raise OrcaError(f"non-JSON output from {cli}: {out[:300]}") from exc
    if not payload.get("ok", False):
        err = payload.get("error") or {}
        raise OrcaError(f"{err.get('code', 'unknown')}: {err.get('message', '')}")
    return payload.get("result", {})


def read_terminal(cli: str, handle: str, cursor: str | None) -> tuple[list[str], str | None]:
    _guard(handle)
    args = ["terminal", "read", "--terminal", handle, "--json"]
    if cursor is not None:
        args += ["--cursor", str(cursor)]
    try:
        term = _json(cli, args)["terminal"]
    except OrcaError as exc:
        if "terminal_handle_stale" in str(exc):
            raise OrcaError("terminal handle is stale — Orca restarted; "
                            "list terminals and create a new one, then ask the user "
                            "to authenticate again") from exc
        raise
    return term.get("tail", []), term.get("latestCursor")


def send_text(cli: str, handle: str, text: str) -> None:
    _guard(handle)
    _json(cli, ["terminal", "send", "--terminal", handle, "--enter", "--json", "--text", text])


def cmd_list(cli: str, _args) -> int:
    """Only terminals this tool created, and never their output.

    Orca's listing is worktree-wide and includes previews of every tab — including the
    agent's own. Neither the other handles nor their content are returned here.
    """
    allowed = _load_created()
    hidden = 0
    for term in _json(cli, ["terminal", "list", "--json"]).get("terminals", []):
        handle = term.get("handle", "")
        if handle in allowed:
            print(f"{handle}\t{term.get('title', '')}")
        else:
            hidden += 1
    if hidden:
        print(f"# {hidden} other terminal(s) withheld: out of scope for this tool",
              file=sys.stderr)
    return 0


def cmd_create(cli: str, args) -> int:
    cmd = ["terminal", "create", "--json", "--title", args.title]
    if args.worktree:
        cmd += ["--worktree", args.worktree]
    if args.command:
        cmd += ["--command", args.command]
    term = _json(cli, cmd)["terminal"]
    _remember(term["handle"], term.get("title", ""))
    print(term["handle"])
    print(f"# title={term.get('title')} worktree={term.get('worktreeId')}", file=sys.stderr)
    return 0


def cmd_read(cli: str, args) -> int:
    tail, cursor = read_terminal(cli, args.terminal, args.cursor)
    for line in tail[-args.lines:] if args.lines else tail:
        print(line)
    print(f"# cursor={cursor}", file=sys.stderr)
    return 0


def cmd_send(cli: str, args) -> int:
    send_text(cli, args.terminal, args.text)
    return 0


def cmd_send_script(cli: str, args) -> int:
    body = open(args.file, "rb").read()
    if not body:
        raise OrcaError(f"{args.file} is empty")
    payload = base64.b64encode(body).decode()
    send_text(cli, args.terminal, f"echo {payload} | base64 -d | bash")
    return 0


def cmd_wait_prompt(cli: str, args) -> int:
    pattern = re.compile(args.pattern)
    deadline = time.time() + args.timeout
    cursor = args.cursor
    while time.time() < deadline:
        tail, cursor = read_terminal(cli, args.terminal, cursor)
        if tail and any(pattern.search(line) for line in tail):
            print(f"matched; cursor={cursor}")
            return 0
        time.sleep(args.interval)
    print(f"timeout after {args.timeout}s waiting for /{args.pattern}/", file=sys.stderr)
    return 1


def cmd_wait_quiet(cli: str, args) -> int:
    """Wait until no new output has appeared for `quiet` seconds."""
    cursor = args.cursor
    last_change = time.time()
    deadline = time.time() + args.timeout
    collected: list[str] = []
    while time.time() < deadline:
        tail, new_cursor = read_terminal(cli, args.terminal, cursor)
        if tail:
            collected.extend(tail)
            cursor = new_cursor
            last_change = time.time()
        elif time.time() - last_change >= args.quiet:
            break
        time.sleep(args.interval)
    for line in collected:
        print(line)
    print(f"# cursor={cursor}", file=sys.stderr)
    return 0


def cmd_run_script(cli: str, args) -> int:
    cmd_send_script(cli, args)
    ns = argparse.Namespace(terminal=args.terminal, cursor=None,
                            quiet=args.quiet, timeout=args.timeout, interval=2)
    return cmd_wait_quiet(cli, ns)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--orca", help="path to the orca executable (otherwise auto-resolved)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list").set_defaults(fn=cmd_list)

    p = sub.add_parser("create")
    p.add_argument("--title", required=True)
    p.add_argument("--command", default=None)
    p.add_argument("--worktree", default="active")
    p.set_defaults(fn=cmd_create)

    p = sub.add_parser("read")
    p.add_argument("--terminal", required=True)
    p.add_argument("--cursor", default=None)
    p.add_argument("--lines", type=int, default=0)
    p.set_defaults(fn=cmd_read)

    p = sub.add_parser("send")
    p.add_argument("--terminal", required=True)
    p.add_argument("--text", required=True)
    p.set_defaults(fn=cmd_send)

    p = sub.add_parser("send-script")
    p.add_argument("--terminal", required=True)
    p.add_argument("--file", required=True)
    p.set_defaults(fn=cmd_send_script)

    p = sub.add_parser("wait-prompt")
    p.add_argument("--terminal", required=True)
    p.add_argument("--pattern", required=True)
    p.add_argument("--timeout", type=float, default=150)
    p.add_argument("--interval", type=float, default=5)
    p.add_argument("--cursor", default=None)
    p.set_defaults(fn=cmd_wait_prompt)

    p = sub.add_parser("wait-quiet")
    p.add_argument("--terminal", required=True)
    p.add_argument("--quiet", type=float, default=4)
    p.add_argument("--timeout", type=float, default=180)
    p.add_argument("--interval", type=float, default=2)
    p.add_argument("--cursor", default=None)
    p.set_defaults(fn=cmd_wait_quiet)

    p = sub.add_parser("run-script")
    p.add_argument("--terminal", required=True)
    p.add_argument("--file", required=True)
    p.add_argument("--quiet", type=float, default=4)
    p.add_argument("--timeout", type=float, default=240)
    p.set_defaults(fn=cmd_run_script)

    args = parser.parse_args(argv)
    # Handles pasted from a Windows shell often carry a trailing \r; strip it so the
    # allowlist comparison is about the handle, not the line ending.
    if getattr(args, "terminal", None):
        args.terminal = args.terminal.strip()
    cli = resolve_cli(args.orca)
    try:
        return args.fn(cli, args)
    except OrcaError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
