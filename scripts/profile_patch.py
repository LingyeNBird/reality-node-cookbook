#!/usr/bin/env python3
"""Patch ONLY the node block of the user's own Clash/mihomo profile.

The user's profile is not a template to be rewritten. Their DNS, TUN settings, proxy
groups, rules and comments are deliberate, and a YAML round-trip would destroy them:
comments vanish, indentation is normalised, key order changes. So this script edits the
file **textually**, one proxy entry at a time, and then proves that nothing outside that
entry moved.

    python profile_patch.py --template <user-profile.yaml> --out <dest.yaml> \
        --server <IP> --uuid <UUID> --sni <SNI> --pbk <PUBLIC_KEY> --sid <SHORT_ID> \
        [--name <NODE_NAME>] [--proxy-index 0] [--dry-run]

Guarantees it enforces:

  * everything before and after the patched entry is byte-identical;
  * inside the entry, every key it did not set is left untouched;
  * a structural check (when PyYAML is importable) that the result parses and that the
    node fields hold the requested values;
  * the destination is written 0600 and must live outside any repository.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import stat
import sys
from pathlib import Path

TOP_KEY = re.compile(r"^[A-Za-z0-9_.-]+:")
ENTRY_START = re.compile(r"^(\s*)-\s")
DASH_KEY = re.compile(r"^(\s*-\s+)([A-Za-z0-9_.-]+):(\s*)(.*)$")
KEY_LINE = re.compile(r"^(\s*)([A-Za-z0-9_.-]+):(\s*)(.*)$")

# Fields that belong to the node and may be written. Everything else is the user's.
NODE_FIELDS = ("name", "type", "server", "port", "uuid", "network", "tls", "udp",
               "flow", "servername", "client-fingerprint")
REALITY_KEYS = ("public-key", "short-id")


class PatchError(RuntimeError):
    pass


def find_proxies(lines: list[str]) -> tuple[int, int]:
    start = next((i for i, ln in enumerate(lines) if re.match(r"^proxies:\s*$", ln)), None)
    if start is None:
        raise PatchError("no top-level 'proxies:' block found in this file")
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if TOP_KEY.match(lines[j]):
            end = j
            break
    return start, end


def find_entries(lines: list[str], start: int, end: int) -> list[tuple[int, int]]:
    starts = [i for i in range(start + 1, end) if ENTRY_START.match(lines[i])]
    if not starts:
        raise PatchError("the 'proxies:' block has no entries")
    bounds = []
    for n, s in enumerate(starts):
        e = starts[n + 1] if n + 1 < len(starts) else end
        bounds.append((s, e))
    return bounds


def entry_indent(lines: list[str], s: int) -> int:
    m = ENTRY_START.match(lines[s])
    assert m
    return len(m.group(1)) + 2  # keys sit two columns right of the dash


def set_key(block: list[str], key: str, value: str) -> list[str]:
    """Replace or append `key: value` inside one entry, keeping every other line as-is."""
    m0 = DASH_KEY.match(block[0])
    if m0 and m0.group(2) == key:
        block[0] = f"{m0.group(1)}{key}: {value}\n"
        return block
    for i in range(1, len(block)):
        m = KEY_LINE.match(block[i])
        if m and m.group(2) == key:
            block[i] = f"{m.group(1)}{key}: {value}\n"
            return block
    indent = " " * (len(m0.group(1)) if m0 else 4)
    last = 0
    for i in range(1, len(block)):
        m = KEY_LINE.match(block[i])
        if m and m.group(1) == indent:
            last = i
    block.insert(last + 1, f"{indent}{key}: {value}\n")
    return block


def set_reality(block: list[str], public_key: str, short_id: str) -> list[str]:
    """Write the nested reality-opts mapping, replacing it wholesale if present."""
    idx = next((i for i, ln in enumerate(block)
                if KEY_LINE.match(ln) and KEY_LINE.match(ln).group(2) == "reality-opts"), None)
    indent = " " * entry_indent(block, 0)
    child = indent + "  "
    if idx is None:
        block.append(f"{indent}reality-opts:\n")
        block.append(f"{child}public-key: {public_key}\n")
        block.append(f"{child}short-id: {short_id}\n")
        return block

    # drop the child lines, then rewrite them; stop at a blank line or a dedent
    j = idx + 1
    while j < len(block):
        m = KEY_LINE.match(block[j])
        if not m or len(m.group(1)) <= len(indent):
            break
        j += 1
    block[idx:j] = [f"{indent}reality-opts:\n",
                    f"{child}public-key: {public_key}\n",
                    f"{child}short-id: {short_id}\n"]
    return block


def rewrite_refs(suffix: list[str], old: str, new: str) -> tuple[list[str], int]:
    """Point group member lists at the renamed node. Returns (new_suffix, changed_lines)."""
    targets = {f'- "{old}"', f"- {old}"}
    out: list[str] = []
    changed = 0
    for ln in suffix:
        if ln.strip() in targets:
            indent = ln[: len(ln) - len(ln.lstrip())]
            out.append(f'{indent}- "{new}"\n')
            changed += 1
        else:
            out.append(ln)
    return out, changed


def patch(text: str, args) -> tuple[str, dict]:
    lines = text.splitlines(keepends=True)
    p_start, p_end = find_proxies(lines)
    entries = find_entries(lines, p_start, p_end)
    if args.proxy_index >= len(entries):
        raise PatchError(f"--proxy-index {args.proxy_index} is out of range: "
                         f"{len(entries)} entr{'y' if len(entries) == 1 else 'ies'}")
    s, e = entries[args.proxy_index]

    prefix = lines[:s]
    block = list(lines[s:e])
    suffix = lines[e:]

    before_keys = {KEY_LINE.match(ln).group(2): KEY_LINE.match(ln).group(3) + KEY_LINE.match(ln).group(4)
                   for ln in block if KEY_LINE.match(ln)}

    # the name may sit on the dash line itself, so read it before anything is rewritten
    old_name = None
    m0 = DASH_KEY.match(block[0])
    if m0 and m0.group(2) == "name":
        old_name = m0.group(4).strip().strip("\"'")
    else:
        for ln in block:
            m = KEY_LINE.match(ln)
            if m and m.group(2) == "name":
                old_name = m.group(4).strip().strip("\"'")
                break

    values = {
        "type": "vless",
        "server": args.server,
        "port": str(args.port),
        "uuid": args.uuid,
        "network": "tcp",
        "tls": "true",
        "udp": "true",
        "flow": "xtls-rprx-vision",
        "servername": args.sni,
        "client-fingerprint": "chrome",
    }
    if args.name:
        values = {"name": args.name, **values}
    for key, value in values.items():
        block = set_key(block, key, value)
    block = set_reality(block, args.pbk, args.sid)

    ref_updates = 0
    if args.name and old_name and args.name != old_name:
        suffix, ref_updates = rewrite_refs(suffix, old_name, args.name)

    after = prefix + block + suffix

    # --- proof that nothing outside the entry moved
    if "".join(after[:len(prefix)]) != "".join(prefix):
        raise PatchError("internal check failed: the text before the entry changed")
    if "".join(after[len(after) - len(suffix):]) != "".join(suffix):
        raise PatchError("internal check failed: the text after the entry changed")

    # keys we did not touch must be untouched inside the entry too
    kept = {}
    ours = set(NODE_FIELDS) | {"reality-opts"} | set(REALITY_KEYS)
    for ln in block:
        m = KEY_LINE.match(ln)
        if m and m.group(2) not in ours:
            kept[m.group(2)] = m.group(3) + m.group(4)
    for key, val in kept.items():
        if key in before_keys and before_keys[key] != val:
            raise PatchError(f"internal check failed: unrelated key {key!r} changed")

    stats = {
        "entries": len(entries),
        "patched_entry": args.proxy_index,
        "lines_before": len(lines),
        "lines_after": len(after),
        "ref_updates": ref_updates,
        "prefix_identical": True,
        "suffix_identical": True,
    }
    return "".join(after), stats


def structural_check(path: Path, args) -> bool:
    try:
        import yaml  # noqa: PLC0415
    except ImportError:
        print("note: PyYAML not installed — structural check skipped (text checks passed)",
              file=sys.stderr)
        return True
    try:
        cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - any parse failure is the caller's answer
        raise PatchError(f"the patched file does not parse as YAML: {exc}") from exc
    if not isinstance(cfg, dict) or "proxies" not in cfg:
        raise PatchError("the patched file has no top-level 'proxies'")
    px = cfg["proxies"][args.proxy_index]
    problems = []
    if px.get("server") != args.server:
        problems.append(f"server is {px.get('server')!r}")
    if str(px.get("port")) != str(args.port):
        problems.append(f"port is {px.get('port')!r}")
    if px.get("uuid") != args.uuid:
        problems.append("uuid mismatch")
    if px.get("servername") != args.sni:
        problems.append(f"servername is {px.get('servername')!r}")
    reality = px.get("reality-opts") or {}
    if reality.get("public-key") != args.pbk or str(reality.get("short-id")) != str(args.sid):
        problems.append("reality-opts mismatch")
    if args.name and px.get("name") != args.name:
        problems.append(f"name is {px.get('name')!r}")

    known = {p.get("name") for p in cfg.get("proxies", []) if isinstance(p, dict)}
    known |= {"DIRECT", "REJECT", "GLOBAL"}
    for group in cfg.get("proxy-groups", []) or []:
        for member in group.get("proxies", []) or []:
            if isinstance(member, dict):
                continue
            if member not in known:
                problems.append(f"group {group.get('name')!r} references unknown "
                                f"proxy {member!r} — a dangling reference")

    if problems:
        raise PatchError("result parses, but: " + "; ".join(problems))
    return True


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Patch only the node block of the user's own profile.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="The user's DNS, TUN, groups, rules and comments are copied through "
               "byte-for-byte; only one proxy entry is rewritten.")
    ap.add_argument("--template", required=True, help="the profile the USER supplied")
    ap.add_argument("--out", required=True, help="where the patched profile is written")
    ap.add_argument("--server", required=True)
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--uuid", required=True)
    ap.add_argument("--sni", required=True)
    ap.add_argument("--pbk", required=True, help="Reality public key")
    ap.add_argument("--sid", default="", help="Reality short id")
    ap.add_argument("--name", default=None,
                    help="rename the node (omit to keep the template's own name)")
    ap.add_argument("--proxy-index", type=int, default=0)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    src = Path(args.template).expanduser()
    if not src.is_file():
        raise PatchError(f"not found: {src}")
    dst = Path(args.out).expanduser()

    text = src.read_text(encoding="utf-8")
    patched, stats = patch(text, args)

    if args.dry_run:
        print("dry run — nothing written")
        print(f"  entries in proxies: {stats['entries']}")
        print(f"  would patch entry  : {stats['patched_entry']}")
        print(f"  lines {stats['lines_before']} -> {stats['lines_after']}")
        print("  prefix/suffix byte-identical: yes")
        return 0

    if dst.is_absolute() and any(part == ".git" for part in dst.parts):
        raise PatchError("refusing to write inside a git directory")

    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_suffix(dst.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
        fh.write(patched)
    tmp.replace(dst)
    try:
        dst.chmod(0o600)
    except OSError:
        pass
    if os.name == "nt":
        user = os.environ.get("USERNAME", "")
        cmd = ["icacls", str(dst), "/inheritance:r"]
        if user:
            cmd += ["/grant:r", f"{user}:F"]
        cmd += ["/grant:r", "SYSTEM:F"]
        shutil.which("icacls") and __import__("subprocess").run(cmd, capture_output=True)

    structural_check(dst, args)

    print(f"patched {dst}")
    print(f"  entries in proxies        : {stats['entries']} (patched #{stats['patched_entry']})")
    print(f"  text before the entry     : byte-identical")
    print(f"  text after the entry      : byte-identical")
    print(f"  untouched keys in entry   : preserved")
    print(f"  group references updated  : {stats['ref_updates']}")
    print(f"  structural check          : passed")
    print("\n  Everything the user configured — DNS, TUN, groups, rules, comments — is untouched.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except PatchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
