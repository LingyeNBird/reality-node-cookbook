#!/usr/bin/env python3
"""Generate an encrypted Ed25519 key and its passphrase file — on the client machine.

This step is local on purpose: the private key must never exist on the node, and only the
`.pub` is ever uploaded. It is Python rather than shell so the very first step of the
runbook does not depend on Git Bash, WSL or any other POSIX layer being installed on a
Windows workstation, and so file permissions are handled with the mechanism the platform
actually enforces (`chmod` on POSIX, `icacls` on Windows).

    python ssh_keygen.py --dir <artifact-dir> [--name id_ed25519] [--bytes 32] [--kdf 100]
    python ssh_keygen.py --dir <artifact-dir> --dry-run

Produces, inside the directory the user chose:

    <name>                  private key, 0600 (owner-only ACL on Windows)
    <name>.pub
    <name>.passphrase.txt   the generated passphrase, 0600, temporary

The passphrase exists in exactly two places: that file, and the ssh-keygen invocation
that encrypts the key. It is never printed, and strength is enforced — 32 random bytes
(256 bits) by default, with a hard floor of 24 bytes (192 bits).
"""
from __future__ import annotations

import argparse
import base64
import datetime
import os
import secrets
import shutil
import socket
import stat
import subprocess
import sys
from pathlib import Path

MIN_BYTES = 24
DEFAULT_BYTES = 32
DEFAULT_KDF = 100


def die(msg: str, code: int = 1) -> "NoReturn":  # type: ignore[valid-type]
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(code)


def restrict_permissions(directory: Path, files: list[Path]) -> None:
    """Apply the mechanism the platform actually enforces."""
    try:
        directory.chmod(0o700)
    except OSError:
        pass
    if os.name == "nt":
        user = os.environ.get("USERNAME", "")
        grants = [f"{user}:(OI)(CI)F", "SYSTEM:(OI)(CI)F"] if user else ["SYSTEM:(OI)(CI)F"]
        cmd = ["icacls", str(directory), "/inheritance:r"]
        for grant in grants:
            cmd += ["/grant:r", grant]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            print("warning: icacls failed; check the ACLs on this directory by hand",
                  file=sys.stderr)
    else:
        for f in files:
            try:
                f.chmod(0o600)
            except OSError:
                pass


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Generate an encrypted Ed25519 key and its passphrase file.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Refuses to overwrite an existing key, and refuses a passphrase below the "
               "entropy floor instead of accepting a weak one.")
    ap.add_argument("--dir", required=True, help="artifact directory (created 0700)")
    ap.add_argument("--name", default="id_ed25519")
    ap.add_argument("--bytes", type=int, default=DEFAULT_BYTES,
                    help=f"random bytes of entropy (default {DEFAULT_BYTES} = 256 bits, "
                         f"floor {MIN_BYTES})")
    ap.add_argument("--kdf", type=int, default=DEFAULT_KDF, help="ssh-keygen -a rounds")
    ap.add_argument("--comment", default=None, help="key comment (default: host-date)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    if args.bytes < MIN_BYTES:
        die(f"{args.bytes} bytes is below the {MIN_BYTES}-byte floor "
            f"({MIN_BYTES * 8} bits of entropy)", 2)
    if args.kdf < 1:
        die("--kdf must be at least 1", 2)

    keygen = shutil.which("ssh-keygen")
    if not keygen:
        die("ssh-keygen not found on PATH (it ships with OpenSSH)", 2)

    directory = Path(args.dir).expanduser()
    key = directory / args.name
    pub = directory / f"{args.name}.pub"
    pwfile = directory / f"{args.name}.passphrase.txt"

    if key.exists():
        die(f"{key} already exists — never overwrite a key")

    if args.dry_run:
        print(f"would create {key}  (ed25519, -a {args.kdf})")
        print(f"would create {pub}")
        print(f"would create {pwfile}  ({args.bytes} random bytes, mode 0600)")
        print(f"directory exists: {'yes' if directory.is_dir() else 'no'}")
        return 0

    directory.mkdir(parents=True, exist_ok=True)

    # Generated here and never printed: 32 bytes of base64 is 43 characters.
    passphrase = base64.b64encode(secrets.token_bytes(args.bytes)).decode("ascii").rstrip("=")
    if passphrase.startswith("-"):
        passphrase = "A" + passphrase
    if len(passphrase) < 32:
        die("generated passphrase came out shorter than 32 characters")

    comment = args.comment or f"{socket.gethostname()}-{datetime.date.today():%Y%m%d}"

    proc = subprocess.run(
        [keygen, "-q", "-t", "ed25519", "-a", str(args.kdf), "-f", str(key),
         "-N", passphrase, "-C", comment],
        capture_output=True, text=True)
    if proc.returncode != 0:
        die(f"ssh-keygen failed: {(proc.stderr or proc.stdout).strip()}")

    # 0600 from creation, not after the fact.
    fd = os.open(pwfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(passphrase + "\n")
    del passphrase

    restrict_permissions(directory, [key, pub, pwfile])

    # Prove the passphrase is actually in effect, without revealing anything.
    check = subprocess.run([keygen, "-y", "-P", "", "-f", str(key)],
                           capture_output=True, text=True)
    if check.returncode == 0:
        for p in (key, pub, pwfile):
            try:
                p.unlink()
            except OSError:
                pass
        die("the key opens with an empty passphrase — encryption is not in effect")

    fingerprint = subprocess.run([keygen, "-l", "-f", str(pub)],
                                 capture_output=True, text=True).stdout.strip()
    print(f"--- artifact directory: {directory}")
    for p in (key, pub, pwfile):
        print(f"    {p.name:28} {p.stat().st_size:>5} bytes")
    print()
    print(f"public key  : {pub.read_text(encoding='utf-8').strip()}")
    print(f"fingerprint : {fingerprint}")
    print(f"passphrase  : stored in {pwfile} (0600) — deliberately not printed")
    print()
    print("Copy that passphrase into your password manager, then delete the file:")
    print(f"  {pwfile}")
    print("Until it is deleted, this directory is a credential: keep it out of any repository.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
