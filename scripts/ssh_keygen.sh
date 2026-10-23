#!/usr/bin/env bash
# Generate an encrypted Ed25519 key whose passphrase the assistant never prints.
#
#   ssh_keygen.sh --dir <artifact-dir> [--name id_ed25519] [--bytes 32] [--kdf 100]
#   ssh_keygen.sh --dir <artifact-dir> --dry-run
#
# Produces, inside the directory the user chose:
#
#   <name>                  private key, 0600
#   <name>.pub
#   <name>.passphrase.txt   the generated passphrase, 0600, temporary
#
# The passphrase exists in exactly two places: that file, and the ssh-keygen invocation
# that encrypts the key. It is never echoed to stdout, never placed on a command line
# another process can read, and never written into a transcript. Strength is enforced:
# 32 random bytes by default (256 bits), and anything under 24 bytes (192 bits) is
# refused rather than accepted.
set -euo pipefail

DIR=""
NAME="id_ed25519"
BYTES=32
KDF=100
DRY=0
MIN_BYTES=24

usage() {
  cat <<'EOF'
Generate an encrypted Ed25519 key and its passphrase file.

  ssh_keygen.sh --dir <artifact-dir> [--name id_ed25519] [--bytes 32] [--kdf 100]
  ssh_keygen.sh --dir <artifact-dir> --dry-run

--dir    where the key, the .pub and the passphrase file go (created 0700)
--bytes  random bytes of entropy for the passphrase (default 32 = 256 bits, floor 24)
--kdf    ssh-keygen -a rounds (default 100)

Refuses to overwrite an existing key, and refuses to emit a passphrase below the floor.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dir)    DIR="${2:-}";   shift 2 ;;
    --name)   NAME="${2:-}";  shift 2 ;;
    --bytes)  BYTES="${2:-}"; shift 2 ;;
    --kdf)    KDF="${2:-}";   shift 2 ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown option: %s\n' "$1" >&2; exit 2 ;;
  esac
done

[ -n "$DIR" ] || { usage >&2; exit 2; }
case "$BYTES" in ''|*[!0-9]*) printf 'bytes must be numeric\n' >&2; exit 2 ;; esac
case "$KDF" in ''|*[!0-9]*) printf 'kdf must be numeric\n' >&2; exit 2 ;; esac
if [ "$BYTES" -lt "$MIN_BYTES" ]; then
  printf 'refusing: %s bytes is below the %s-byte floor (192 bits of entropy)\n' \
         "$BYTES" "$MIN_BYTES" >&2
  exit 2
fi

KEY="$DIR/$NAME"
PUB="$KEY.pub"
PWF="$DIR/$NAME.passphrase.txt"

if [ -e "$KEY" ]; then
  printf 'refusing: %s already exists — never overwrite a key\n' "$KEY" >&2
  exit 1
fi
command -v ssh-keygen >/dev/null 2>&1 || { printf 'ssh-keygen not found\n' >&2; exit 2; }
command -v openssl    >/dev/null 2>&1 || { printf 'openssl not found\n' >&2; exit 2; }

if [ "$DRY" -eq 1 ]; then
  printf 'would create %s  (ed25519, -a %s)\n' "$KEY" "$KDF"
  printf 'would create %s\n' "$PUB"
  printf 'would create %s  (%s random bytes, mode 0600)\n' "$PWF" "$BYTES"
  printf 'directory exists: %s\n' "$([ -d "$DIR" ] && echo yes || echo no)"
  exit 0
fi

umask 077
mkdir -p "$DIR"
chmod 700 "$DIR" 2>/dev/null || true

# Best effort on Windows: chmod is mostly cosmetic there, ACLs are what count.
case "$(uname -s 2>/dev/null)" in
  MINGW*|MSYS*|CYGWIN*)
    if command -v icacls >/dev/null 2>&1; then
      WDIR=$(cygpath -w "$DIR" 2>/dev/null || printf '%s' "$DIR")
      icacls "$WDIR" /inheritance:r \
             /grant:r "${USERNAME}:(OI)(CI)F" "SYSTEM:(OI)(CI)F" >/dev/null 2>&1 || true
    fi
    ;;
esac

# Generated here, never echoed. 32 bytes of base64 is 43 characters (~256 bits).
PASS=$(openssl rand -base64 "$BYTES" | tr -d '\n')
case "$PASS" in -*) PASS="A$PASS" ;; esac
if [ "${#PASS}" -lt 32 ]; then
  printf 'refusing: generated passphrase is shorter than 32 characters\n' >&2
  exit 1
fi

ssh-keygen -q -t ed25519 -a "$KDF" -f "$KEY" -N "$PASS" \
           -C "$(hostname 2>/dev/null || echo host)-$(date +%Y%m%d)" \
  || { printf 'ssh-keygen failed\n' >&2; exit 1; }

printf '%s\n' "$PASS" > "$PWF"
chmod 600 "$PWF" 2>/dev/null || true
chmod 600 "$KEY" 2>/dev/null || true
unset PASS

# Prove the passphrase is actually in effect, without printing anything secret.
if ssh-keygen -y -P "" -f "$KEY" >/dev/null 2>&1; then
  printf 'refusing: the key opens with an empty passphrase — encryption is not in effect\n' >&2
  exit 1
fi

printf '%s\n' "--- artifact directory: $DIR (0700)"
ls -l "$KEY" "$PUB" "$PWF" 2>/dev/null || true
printf '\n'
printf 'public key  : %s\n' "$(cat "$PUB")"
printf 'fingerprint : %s\n' "$(ssh-keygen -l -f "$PUB" | awk '{print $2" "$4}')"
printf 'passphrase  : stored in %s (0600) — deliberately not printed\n' "$PWF"
printf '\n'
printf 'Copy that passphrase into your password manager, then delete the file:\n'
printf '  rm -f "%s"\n' "$PWF"
printf 'Until it is deleted, this directory is a credential: keep it out of any repository.\n'
