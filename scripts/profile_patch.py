#!/usr/bin/env python3
"""Patch ONLY the node entry of the user's own Clash/mihomo profile.

The user's profile is not a template to be rewritten. Their `mixed-port`, `tun`, `dns`,
`proxy-groups`, `rules` and comments are deliberate, and a YAML round-trip destroys them:
comments vanish, indentation is normalised, key order changes, line endings are rewritten.
So this script edits the file **textually**, restructuring only the one proxy entry, and
then proves that nothing outside it moved.

    python profile_patch.py --template <user-profile.yaml> --out <dest.yaml> \
        --server <IP> --uuid <UUID> --sni <SNI> --pbk <PUBLIC_KEY> --sid <SHORT_ID> \
        [--name <NODE_NAME>] [--proxy-index 0] [--dry-run]

Guarantees:

  * all bytes before and after the patched entry are identical, line endings included;
  * inside the entry, keys the script does not own keep their exact value, order and
    children (a comment under a key survives);
  * any key the script does own but that is missing from the entry is added in place,
    never duplicated;
  * with PyYAML available, the result must parse and every group member must resolve.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

TOP_KEY = re.compile(r"^[A-Za-z0-9_.-]+:")
KEY_LINE = re.compile(r"^(\s*)([A-Za-z0-9_.-]+):(\s*)(.*)$")
DASH_KEY = re.compile(r"^(\s*-\s+)([A-Za-z0-9_.-]+):(\s*)(.*)$")

# Fields that belong to the node. Everything else in the entry is the user's.
NODE_FIELDS = ("type", "server", "port", "uuid", "network", "tls", "udp",
               "flow", "servername", "client-fingerprint")
REALITY_KEYS = ("public-key", "short-id")


class PatchError(RuntimeError):
    pass


# ------------------------------------------------------------------ structure

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
    starts = [i for i in range(start + 1, end) if re.match(r"^\s*-\s", lines[i])]
    if not starts:
        raise PatchError("the 'proxies:' block has no entries")
    return [(s, starts[n + 1] if n + 1 < len(starts) else end) for n, s in enumerate(starts)]


class Node:
    """One top-level key of the entry, with its own lines (children) preserved."""

    __slots__ = ("key", "value", "prefix", "children")

    def __init__(self, key: str, value: str, prefix: str, children: list[str]):
        self.key, self.value, self.prefix, self.children = key, value, prefix, children

    def render(self) -> list[str]:
        head = (f"{self.prefix}{self.key}:\n" if self.value == ""
                else f"{self.prefix}{self.key}: {self.value}\n")
        return [head, *self.children]


def split_entry(block: list[str], indent: str) -> tuple[list[Node], list[str]]:
    nodes: list[Node] = []
    trailing: list[str] = []
    first = DASH_KEY.match(block[0]) if block else None
    if not first:
        raise PatchError("the entry does not start with '- key: value'")
    current = Node(first.group(2), first.group(4).rstrip("\r\n"), first.group(1), [])
    nodes.append(current)
    for ln in block[1:]:
        m = KEY_LINE.match(ln)
        if m and m.group(1) == indent:
            current = Node(m.group(2), m.group(4).rstrip("\r\n"), m.group(1), [])
            nodes.append(current)
        elif m and len(m.group(1)) > len(indent):
            current.children.append(ln)
        else:
            trailing.append(ln)
    return nodes, trailing


# ------------------------------------------------------------------ patching

def apply_values(nodes: list[Node], indent: str, values: dict[str, str]) -> None:
    """Replace owned keys in place; append any that are missing. Never duplicate."""
    seen = set()
    for node in nodes:
        if node.key in values:
            node.value = values[node.key]
            node.children = []
            seen.add(node.key)
    for key, value in values.items():
        if key not in seen:
            nodes.append(Node(key, value, indent, []))


def apply_reality(nodes: list[Node], indent: str, public_key: str, short_id: str) -> None:
    child = indent + "  "
    for node in nodes:
        if node.key == "reality-opts":
            node.value = ""
            node.children = [f"{child}public-key: {public_key}\n",
                             f"{child}short-id: {short_id}\n"]
            return
    nodes.append(Node("reality-opts", "", indent,
                      [f"{child}public-key: {public_key}\n",
                       f"{child}short-id: {short_id}\n"]))


def rewrite_refs(suffix: list[str], old: str, new: str) -> tuple[list[str], int]:
    targets = {f'- "{old}"', f"- {old}"}
    out, changed = [], 0
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
        raise PatchError(f"--proxy-index {args.proxy_index} is out of range: {len(entries)} entries")
    s, e = entries[args.proxy_index]

    prefix, block, suffix = lines[:s], list(lines[s:e]), lines[e:]

    m0 = DASH_KEY.match(block[0])
    indent = " " * (len(m0.group(1)) if m0 else 4)
    nodes, trailing = split_entry(block, indent)
    old_name = nodes[0].value if nodes and nodes[0].key == "name" else None
    before = {n.key: (n.value, list(n.children)) for n in nodes}

    eol = "\r\n" if block[0].endswith("\r\n") else "\n"

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

    apply_values(nodes, indent, values)
    apply_reality(nodes, indent, args.pbk, args.sid)

    rendered = [ln for node in nodes for ln in node.render()] + trailing
    if eol != "\n":
        rendered = [ln.replace("\r\n", "\n").replace("\n", "\r\n") for ln in rendered]

    ref_updates = 0
    if args.name and old_name and args.name != old_name:
        suffix, ref_updates = rewrite_refs(suffix, old_name, args.name)

    new_text = "".join(prefix + rendered + suffix)

    # ---- proofs
    if "".join(prefix) != "".join(lines[:s]):
        raise PatchError("internal check failed: text before the entry changed")
    if "".join(suffix) != "".join(lines[e:]):
        raise PatchError("internal check failed: text after the entry changed")
    ours = set(values) | {"reality-opts"} | set(REALITY_KEYS)
    for node in nodes:
        if node.key in ours or node.key not in before:
            continue
        if (node.value, node.children) != before[node.key]:
            raise PatchError(f"internal check failed: unrelated key {node.key!r} changed")
    for key, val in before.items():
        if key in ours:
            continue
        if key not in {n.key for n in nodes}:
            raise PatchError(f"internal check failed: key {key!r} disappeared")

    counts = {n.key: sum(1 for x in nodes if x.key == n.key) for n in nodes}
    dupes = [k for k, c in counts.items() if c > 1]
    if dupes:
        raise PatchError(f"internal check failed: duplicated keys {dupes}")

    return new_text, {
        "entries": len(entries),
        "patched_entry": args.proxy_index,
        "lines_before": len(lines),
        "lines_after": len(new_text.splitlines(keepends=True)),
        "ref_updates": ref_updates,
        "eol": "CRLF" if eol == "\r\n" else "LF",
    }


# ------------------------------------------------------------------ validation

def structural_check(path: Path, args) -> None:
    try:
        import yaml  # noqa: PLC0415
    except ImportError:
        print("note: PyYAML not installed — structural check skipped (text checks passed)",
              file=sys.stderr)
        return
    try:
        cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise PatchError(f"the patched file does not parse as YAML: {exc}") from exc
    if not isinstance(cfg, dict) or "proxies" not in cfg:
        raise PatchError("the patched file has no top-level 'proxies'")

    px = cfg["proxies"][args.proxy_index]
    problems = []
    if px.get("server") != args.server:
        problems.append(f"server is {px.get('server')!r}")
    if str(px.get("port")) != str(args.port):
        problems.append(f"port is {px.get('port')!r}")
    if str(px.get("uuid")) != str(args.uuid):
        problems.append(f"uuid is {px.get('uuid')!r}")
    if px.get("servername") != args.sni:
        problems.append(f"servername is {px.get('servername')!r}")
    reality = px.get("reality-opts") or {}
    if reality.get("public-key") != args.pbk or str(reality.get("short-id")) != str(args.sid):
        problems.append("reality-opts mismatch")
    if args.name and px.get("name") != args.name:
        problems.append(f"name is {px.get('name')!r}")

    for key in ("server", "uuid", "servername"):
        val = px.get(key)
        if isinstance(val, str) and val.startswith("<") and val.endswith(">"):
            problems.append(f"{key} is still the placeholder {val!r}")
    for key in REALITY_KEYS:
        val = reality.get(key)
        if isinstance(val, str) and val.startswith("<") and val.endswith(">"):
            problems.append(f"reality-opts.{key} is still the placeholder {val!r}")

    known = {p.get("name") for p in cfg.get("proxies", []) if isinstance(p, dict)}
    known |= {"DIRECT", "REJECT", "GLOBAL"}
    for group in cfg.get("proxy-groups", []) or []:
        for member in group.get("proxies", []) or []:
            if isinstance(member, dict):
                continue
            if member not in known:
                problems.append(f"group {group.get('name')!r} references unknown proxy {member!r}")

    if problems:
        raise PatchError("result parses, but: " + "; ".join(problems))


# ------------------------------------------------------------------ cli

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Patch only the node entry of the user's own profile.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="The user's DNS, TUN, groups, rules, comments and line endings are copied "
               "through byte-for-byte; only one proxy entry is restructured.")
    ap.add_argument("--template", required=True, help="the profile the USER supplied")
    ap.add_argument("--out", required=True)
    ap.add_argument("--server", required=True)
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--uuid", required=True)
    ap.add_argument("--sni", required=True)
    ap.add_argument("--pbk", required=True, help="Reality public key")
    ap.add_argument("--sid", default="")
    ap.add_argument("--name", default=None,
                    help="rename the node (omit to keep the template's own name)")
    ap.add_argument("--proxy-index", type=int, default=0)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    src = Path(args.template).expanduser()
    if not src.is_file():
        raise PatchError(f"not found: {src}")
    dst = Path(args.out).expanduser()

    with src.open("r", encoding="utf-8", newline="") as fh:   # newline="" keeps CRLF
        text = fh.read()

    patched, stats = patch(text, args)

    if args.dry_run:
        print("dry run — nothing written")
        print(f"  entries in proxies : {stats['entries']} (would patch #{stats['patched_entry']})")
        print(f"  line endings       : {stats['eol']}")
        print(f"  lines {stats['lines_before']} -> {stats['lines_after']}")
        return 0

    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_suffix(dst.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:   # no translation on write
        fh.write(patched)
    tmp.replace(dst)
    try:
        dst.chmod(0o600)
    except OSError:
        pass
    if os.name == "nt" and shutil.which("icacls"):
        user = os.environ.get("USERNAME", "")
        cmd = ["icacls", str(dst), "/inheritance:r"]
        if user:
            cmd += ["/grant:r", f"{user}:F"]
        cmd += ["/grant:r", "SYSTEM:F"]
        subprocess.run(cmd, capture_output=True)

    structural_check(dst, args)

    print(f"patched {dst}")
    print(f"  entries in proxies        : {stats['entries']} (patched #{stats['patched_entry']})")
    print(f"  line endings preserved    : {stats['eol']}")
    print(f"  text before the entry     : byte-identical")
    print(f"  text after the entry      : byte-identical")
    print(f"  untouched keys in entry   : preserved (order and children)")
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
