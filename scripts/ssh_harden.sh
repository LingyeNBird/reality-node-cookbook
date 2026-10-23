#!/usr/bin/env bash
# Staged SSH access hardening: install a key, move the port, turn password auth off.
#
# Run this ON the server, from an already-authenticated session. Every step is small and
# separately verifiable, and none of them closes the old path before the new one is
# proven from outside. That ordering is the whole point: an SSH change that cannot be
# undone without a working login is how people lose servers.
#
#   ssh_harden.sh status                      # show effective policy and where it comes from
#   ssh_harden.sh preflight                   # recon + the traps that apply to this host
#   ssh_harden.sh install-key <pubkey-file>   # append + fix permissions
#   ssh_harden.sh stage-port <new-port>       # listen on OLD and NEW
#   ssh_harden.sh converge-port <new-port>    # listen on NEW only (run after an outside proof)
#   ssh_harden.sh disable-password            # PasswordAuthentication / KbdInteractive = no
#
# Two traps this script encodes:
#
#  * A drop-in in sshd_config.d CANNOT override a keyword that appears earlier in the main
#    sshd_config, because OpenSSH keeps the FIRST obtained value and Include sits partway
#    down the file. Vendor images routinely set directives above it. `status` shows which
#    source actually wins, and the setters edit that source.
#  * Recent Ubuntu runs ssh socket-activated (ssh.socket with Accept=no), where a `Port`
#    line in sshd_config is inert — ListenStream on the socket unit owns the port.
set -euo pipefail

SSHD_MAIN=/etc/ssh/sshd_config
DROPIN_DIR=/etc/ssh/sshd_config.d
HARDEN_DROPIN="${DROPIN_DIR}/20-hardening.conf"
SOCKET_DROPIN=/etc/systemd/system/ssh.socket.d/10-port.conf
STAMP=$(date +%Y%m%d-%H%M%S)

say()  { printf '=== %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }
warn() { printf '!!  %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

need_root() { [ "$(id -u)" = "0" ] || die "run as root"; }
need_sshd() { [ -f "$SSHD_MAIN" ] || die "$SSHD_MAIN not found"; }

# ------------------------------------------------------------------ detection

include_lineno() {
  grep -n -iE '^[[:space:]]*Include[[:space:]]' "$SSHD_MAIN" 2>/dev/null | head -1 | cut -d: -f1
}

# First live definition of a keyword in the main file, but only above the Include line.
first_live_main() {
  local kw="$1" inc
  inc=$(include_lineno); inc=${inc:-999999}
  grep -n -iE "^[[:space:]]*${kw}[[:space:]]+" "$SSHD_MAIN" 2>/dev/null \
    | awk -F: -v lim="$inc" '$1 < lim {print; exit}'
}

# First drop-in (lexicographic order) that defines the keyword: that one wins.
first_dropin() {
  local kw="$1" f
  for f in $(ls -1 "$DROPIN_DIR"/*.conf 2>/dev/null | sort); do
    if grep -qiE "^[[:space:]]*${kw}[[:space:]]+" "$f"; then
      echo "$f"; return 0
    fi
  done
  return 1
}

socket_activated() { systemctl is-active --quiet ssh.socket 2>/dev/null; }

current_ports() {
  if socket_activated; then
    systemctl show ssh.socket -p Listen --value 2>/dev/null \
      | sed -E 's/.*:([0-9]+).*/\1/' | sort -un | paste -sd' ' -
  else
    sshd -T 2>/dev/null | awk '/^port /{print $2}' | sort -un | paste -sd' ' -
  fi
}

# ------------------------------------------------------------------ mutation

# Rewrite one line in place, preserving the file's mode and ownership.
replace_line() {
  local f="$1" n="$2" text="$3" tmp
  tmp=$(mktemp)
  awk -v n="$n" -v t="$text" 'NR==n{print t; next} {print}' "$f" > "$tmp"
  cat "$tmp" > "$f"
  rm -f "$tmp"
}

# Set a keyword where OpenSSH actually reads it: main file above Include, else the first
# drop-in that defines it, else a new hardening drop-in.
set_effective_keyword() {
  local kw="$1" val="$2" hit f n
  if hit=$(first_live_main "$kw"); then
    n=${hit%%:*}
    replace_line "$SSHD_MAIN" "$n" "${kw} ${val}"
    note "${kw} ${val}   -> ${SSHD_MAIN}:${n}  (above Include, so it wins)"
  elif f=$(first_dropin "$kw"); then
    n=$(grep -niE "^[[:space:]]*${kw}[[:space:]]+" "$f" | head -1 | cut -d: -f1)
    replace_line "$f" "$n" "${kw} ${val}"
    note "${kw} ${val}   -> ${f}:${n}"
  else
    install -d -m 0755 "$DROPIN_DIR"
    printf '%s %s\n' "$kw" "$val" >> "$HARDEN_DROPIN"
    note "${kw} ${val}   -> ${HARDEN_DROPIN} (new)"
  fi
}

backup_sshd() {
  cp -a "$SSHD_MAIN" "${SSHD_MAIN}.bak-${STAMP}"
  note "backup: ${SSHD_MAIN}.bak-${STAMP}"
}

validate() {
  sshd -t || die "sshd -t failed — nothing was reloaded, previous state intact"
  note "sshd -t: ok"
}

reload_ssh() {
  validate
  systemctl reload ssh 2>/dev/null \
    || systemctl reload sshd 2>/dev/null \
    || systemctl restart ssh
  note "reloaded"
}

# ------------------------------------------------------------------ commands

cmd_status() {
  need_sshd
  say "sshd"
  sshd -V 2>&1 | head -1
  note "socket-activated: $(socket_activated && echo yes || echo no)"
  note "listening ports : $(current_ports)"
  if socket_activated; then
    systemctl show ssh.socket -p Listen --value 2>/dev/null | sed 's/^/    /'
  fi
  echo
  say "effective policy (sshd -T)"
  sshd -T 2>/dev/null | grep -Ei \
    '^(port|listenaddress|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|permitrootlogin|maxauthtries)' \
    | sed 's/^/    /'
  echo
  say "where each auth keyword comes from"
  local kw hit f
  for kw in PasswordAuthentication KbdInteractiveAuthentication PubkeyAuthentication PermitRootLogin Port; do
    if hit=$(first_live_main "$kw"); then
      note "$kw <- ${SSHD_MAIN}:${hit%%:*}  (${hit#*:})"
    elif f=$(first_dropin "$kw"); then
      note "$kw <- $f"
    else
      note "$kw <- built-in default (no explicit setting)"
    fi
  done
}

cmd_preflight() {
  need_sshd
  say "host"
  . /etc/os-release 2>/dev/null || true
  note "${PRETTY_NAME:-unknown} $(uname -m)"
  note "uptime: $(uptime -p 2>/dev/null || uptime)"
  echo
  say "ssh"
  sshd -V 2>&1 | head -1
  note "socket-activated: $(socket_activated && echo yes || echo no)"
  note "listening ports : $(current_ports)"
  note "Include line    : $(include_lineno || echo none)"
  echo
  say "traps that apply here"
  local kw
  for kw in PasswordAuthentication Port; do
    if hit=$(first_live_main "$kw"); then
      warn "$kw is set in the main file ABOVE Include (${hit%%:*}): drop-ins cannot override it"
    fi
  done
  socket_activated && warn "ssh.socket owns the port — edit ListenStream, not sshd_config's Port"
  echo
  say "firewall"
  if command -v ufw >/dev/null 2>&1; then ufw status verbose 2>&1 | head -6; else note "no ufw"; fi
  echo
  say "existing backups"
  ls -1 "${SSHD_MAIN}".bak-* 2>/dev/null | tail -5 || note "none"
  echo
  warn "open the NEW port in the provider's cloud firewall before moving; a port that is"
  warn "only open on the host is still unreachable from the internet"
}

cmd_install_key() {
  local pub="${1:-}"
  [ -n "$pub" ] || die "usage: $0 install-key <public-key-file>"
  [ -f "$pub" ] || die "not found: $pub"
  say "installing key from $pub"
  install -d -m 0700 /root/.ssh
  touch /root/.ssh/authorized_keys
  chmod 0600 /root/.ssh/authorized_keys
  local blob
  blob=$(awk '{print $2}' "$pub" | head -1)
  if grep -qF "$blob" /root/.ssh/authorized_keys 2>/dev/null; then
    note "key already present, not duplicating"
  else
    cat "$pub" >> /root/.ssh/authorized_keys
    note "appended"
  fi
  ls -la /root/.ssh
  echo
  warn "now prove a NEW key-only login from outside before changing anything else:"
  warn "  ssh -o PreferredAuthentications=publickey -o IdentitiesOnly=yes -p <current-port> -i <key> root@<host>"
}

cmd_stage_port() {
  local new="${1:-}"
  [ -n "$new" ] || die "usage: $0 stage-port <new-port>"
  local old p
  old=$(current_ports)
  [ -n "$old" ] || die "cannot determine the current ssh port"
  [ "$old" = "$new" ] && die "$new is already the listening port"

  say "staging port $new alongside $old"
  if socket_activated; then
    install -d -m 0755 "$(dirname "$SOCKET_DROPIN")"
    {
      echo '[Socket]'
      echo 'ListenStream='
      for p in $old $new; do
        echo "ListenStream=0.0.0.0:$p"
        echo "ListenStream=[::]:$p"
      done
    } > "$SOCKET_DROPIN"
    note "wrote $SOCKET_DROPIN"
    systemctl daemon-reload
    say "merged listen list — review before it is applied"
    systemctl show ssh.socket -p Listen | sed 's/^/    /'
    systemctl restart ssh.socket
    systemctl restart ssh.service
  else
    install -d -m 0755 "$DROPIN_DIR"
    printf 'Port %s\n' "$new" > "${DROPIN_DIR}/10-extra-port.conf"
    note "wrote ${DROPIN_DIR}/10-extra-port.conf (Port is a list keyword, so both apply)"
    reload_ssh
  fi

  sleep 1
  say "listeners now"
  ss -lntp 2>/dev/null | grep -iE 'ssh' | sed 's/^/    /' || true
  echo
  warn "BOTH ports should be listening. Prove the new one from OUTSIDE, with the key:"
  warn "  ssh -p $new -i <key> root@<host>"
  warn "Only then run: $0 converge-port $new"
}

cmd_converge_port() {
  local new="${1:-}"
  [ -n "$new" ] || die "usage: $0 converge-port <new-port>"
  say "converging to port $new only"

  if socket_activated; then
    {
      echo '[Socket]'
      echo 'ListenStream='
      echo "ListenStream=0.0.0.0:$new"
      echo "ListenStream=[::]:$new"
    } > "$SOCKET_DROPIN"
    systemctl daemon-reload
    systemctl show ssh.socket -p Listen | sed 's/^/    /'
    systemctl restart ssh.socket
    systemctl restart ssh.service
  else
    rm -f "${DROPIN_DIR}/10-extra-port.conf"
    backup_sshd
    local tmp
    tmp=$(mktemp)
    # drop every live Port line, then declare exactly one via a drop-in
    awk 'tolower($1)=="port" && $0 !~ /^[[:space:]]*#/ {next} {print}' "$SSHD_MAIN" > "$tmp"
    cat "$tmp" > "$SSHD_MAIN"; rm -f "$tmp"
    printf 'Port %s\n' "$new" > "${DROPIN_DIR}/10-port.conf"
    note "removed live Port lines from ${SSHD_MAIN}; wrote ${DROPIN_DIR}/10-port.conf"
    reload_ssh
  fi

  sleep 1
  say "listeners now"
  ss -lntp 2>/dev/null | grep -iE 'ssh' | sed 's/^/    /' || true
  warn "re-prove login from outside on $new; the old port should be closed"
}

cmd_disable_password() {
  say "disabling password-style authentication"
  backup_sshd
  set_effective_keyword PasswordAuthentication no
  set_effective_keyword KbdInteractiveAuthentication no
  reload_ssh
  echo
  say "effective policy"
  sshd -T 2>/dev/null | grep -Ei \
    '^(passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|permitrootlogin)' \
    | sed 's/^/    /'
  echo
  warn "prove it from outside: a password-only attempt must be refused, and a key login must"
  warn "still work:  ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password ..."
  note "rollback: cp ${SSHD_MAIN}.bak-${STAMP} ${SSHD_MAIN} && sshd -t && systemctl reload ssh"
}

usage() {
  cat <<'EOF'
Staged SSH access hardening: install a key, move the port, turn password auth off.
Run ON the server from an already-authenticated session.

  ssh_harden.sh status                      effective policy and which file wins
  ssh_harden.sh preflight                   recon plus the traps that apply to this host
  ssh_harden.sh install-key <pubkey-file>   append the key, fix ~/.ssh permissions
  ssh_harden.sh stage-port <new-port>       listen on the old AND new port
  ssh_harden.sh converge-port <new-port>    listen on the new port only
  ssh_harden.sh disable-password            PasswordAuthentication / KbdInteractive = no

Order matters: prove a login from OUTSIDE on the new port between stage-port and
converge-port. A listening socket is not proof; a fresh login is.
EOF
}

case "${1:-}" in
  ""|-h|--help) usage; exit 0 ;;
  status|preflight|install-key|stage-port|converge-port|disable-password) ;;
  *) printf 'error: unknown command: %s (try --help)\n' "$1" >&2; exit 2 ;;
esac

need_root
case "$1" in
  status)            cmd_status ;;
  preflight)         cmd_preflight ;;
  install-key)       shift; cmd_install_key "$@" ;;
  stage-port)        shift; cmd_stage_port "$@" ;;
  converge-port)     shift; cmd_converge_port "$@" ;;
  disable-password)  cmd_disable_password ;;
esac
