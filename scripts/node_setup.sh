#!/usr/bin/env bash
# Provision, or reconfigure, a sing-box VLESS+Reality inbound.
#
#   SNI=<domain> bash node_setup.sh              # first run: generates secrets
#   SNI=<other-domain> bash node_setup.sh        # target swap: secrets are reused
#   SNI=<domain> PORT=443 INSTALL=1 bash node_setup.sh
#
# Safe on an existing deployment: private_key / uuid / short_id are preserved and only
# server_name, handshake.server and listen_port change. The previous config is backed up
# every time, and nothing restarts unless `sing-box check` passes.
#
# The private key is never printed. Only public values (public key, uuid, short id) are,
# because those are what the client profile needs.
set -euo pipefail

# Hard precondition: this runs only inside an Orca-managed session. The flag is exported
# after the user has authenticated; anywhere else it means the caller took a shortcut.
if [ "${ORCA:-}" != "yes" ]; then
  printf 'refusing: ORCA is not "yes" — run this inside the Orca terminal session\n' >&2
  exit 1
fi

SNI="${SNI:?set SNI=<domain>}"
PORT="${PORT:-443}"
NAME="${NAME:-singbox-reality}"
BIN="${BIN:-/usr/local/bin/sing-box}"
CFG_DIR="${CFG_DIR:-/etc/${NAME}}"
CFG="${CFG_DIR}/config.json"
PUBFILE="${CFG_DIR}/public-key"
UNIT_PATH="/etc/systemd/system/${NAME}.service"
SVC_USER="${SVC_USER:-singbox}"
INSTALL="${INSTALL:-0}"

say() { printf '=== %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- binary
if [ ! -x "$BIN" ]; then
  [ "$INSTALL" = "1" ] || die "$BIN missing; re-run with INSTALL=1 or install sing-box first"
  say "installing sing-box"
  command -v curl >/dev/null || die "curl required"
  command -v tar  >/dev/null || die "tar required"
  ver=$(curl -fsS --max-time 25 https://api.github.com/repos/SagerNet/sing-box/releases/latest \
        | grep -oP '"tag_name":\s*"\K[^"]+' | head -1)
  [ -n "$ver" ] || die "could not resolve the latest release tag"
  arch=$(uname -m); case "$arch" in x86_64) arch=amd64;; aarch64) arch=arm64;; esac
  url="https://github.com/SagerNet/sing-box/releases/download/${ver}/sing-box-${ver#v}-linux-${arch}.tar.gz"
  say "downloading ${url}"
  curl -fsSL --max-time 180 -o /tmp/sing-box.tgz "$url"
  sha256sum /tmp/sing-box.tgz
  tar xzf /tmp/sing-box.tgz -C /tmp
  install -m 0755 /tmp/sing-box-*/sing-box "$BIN"
  rm -f /tmp/sing-box.tgz
fi
say "sing-box $("$BIN" version | head -1)"

# ---------------------------------------------------------------- service account
if ! id "$SVC_USER" >/dev/null 2>&1; then
  say "creating system account ${SVC_USER}"
  useradd --system --no-create-home --shell /usr/sbin/nologin \
          --comment 'sing-box service account' "$SVC_USER"
fi

install -d -m 0750 -o root -g "$SVC_USER" "$CFG_DIR"

# ---------------------------------------------------------------- secrets
if [ -f "$CFG" ]; then
  say "existing config found - reusing its secrets"
  cp -a "$CFG" "${CFG}.bak-$(date +%Y%m%d-%H%M%S)"
  PRIV=$(sed -n 's/.*"private_key": *"\([^"]*\)".*/\1/p' "$CFG" | head -1)
  UUID=$(sed -n 's/.*"uuid": *"\([^"]*\)".*/\1/p' "$CFG" | head -1)
  SHORT_ID=$(sed -n 's/.*"short_id": *\["\([^"]*\)"\].*/\1/p' "$CFG" | head -1)
  PUB=$( [ -f "$PUBFILE" ] && cat "$PUBFILE" || true )
  [ -n "$PRIV" ] && [ -n "$UUID" ] && [ -n "$SHORT_ID" ] \
    || die "could not extract secrets from $CFG; refusing to overwrite it"
  [ -n "$PUB" ] || echo "warning: $PUBFILE missing; recompute the client's public key" >&2
else
  say "generating secrets"
  KP=$("$BIN" generate reality-keypair)
  PRIV=$(printf '%s\n' "$KP" | awk -F': ' '/^PrivateKey:/{print $2}')
  PUB=$(printf '%s\n'  "$KP" | awk -F': ' '/^PublicKey:/{print $2}')
  UUID=$("$BIN" generate uuid)
  SHORT_ID=$(openssl rand -hex 8)
  [ -n "$PRIV" ] && [ -n "$PUB" ] && [ -n "$UUID" ] && [ -n "$SHORT_ID" ] \
    || die "secret generation failed"
  printf '%s\n' "$PUB" > "$PUBFILE"
  chown root:"$SVC_USER" "$PUBFILE"; chmod 0640 "$PUBFILE"
fi

# ---------------------------------------------------------------- config
say "writing $CFG (server_name=${SNI}, port=${PORT})"
cat > "$CFG" <<JSON
{
  "log": {"level": "warn", "timestamp": true},
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality-in",
      "listen": "::",
      "listen_port": ${PORT},
      "users": [{"uuid": "${UUID}", "flow": "xtls-rprx-vision"}],
      "tls": {
        "enabled": true,
        "server_name": "${SNI}",
        "reality": {
          "enabled": true,
          "handshake": {"server": "${SNI}", "server_port": 443},
          "private_key": "${PRIV}",
          "short_id": ["${SHORT_ID}"]
        }
      }
    }
  ],
  "outbounds": [{"type": "direct", "tag": "direct"}]
}
JSON
chown "$SVC_USER":"$SVC_USER" "$CFG"
chmod 0600 "$CFG"

# ---------------------------------------------------------------- unit
say "writing $UNIT_PATH"
cat > "$UNIT_PATH" <<UNIT
[Unit]
Description=sing-box VLESS+Reality inbound (TCP/${PORT})
Documentation=https://sing-box.sagernet.org/
Wants=network-online.target nss-lookup.target
After=network-online.target nss-lookup.target

[Service]
Type=simple
User=${SVC_USER}
Group=${SVC_USER}
# :443 needs CAP_NET_BIND_SERVICE when not running as root
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
StateDirectory=${NAME}
StateDirectoryMode=0700
WorkingDirectory=/var/lib/${NAME}
ExecStart=${BIN} run -c ${CFG}
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
# sing-box aborts at startup if AF_NETLINK is missing
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 "$UNIT_PATH"

# ---------------------------------------------------------------- validate and start
say "validating"
"$BIN" check -c "$CFG" || die "config invalid - nothing restarted, previous state intact"

say "restarting ${NAME}"
systemctl daemon-reload
systemctl enable "${NAME}" >/dev/null 2>&1 || true
systemctl restart "${NAME}"
sleep 2

echo
say "state"
printf 'active=%s enabled=%s\n' "$(systemctl is-active "${NAME}")" "$(systemctl is-enabled "${NAME}" 2>/dev/null || echo unknown)"
ss -lntp | grep ":${PORT}" || echo "warning: nothing listening on ${PORT}"
journalctl -u "${NAME}" -n 5 --no-pager || true

cat <<SUMMARY

--------------------------------------------------------------- client values
public_key  ${PUB}
uuid        ${UUID}
short_id    ${SHORT_ID}
server_name ${SNI}
port        ${PORT}
---------------------------------------------------------------
The private key stays in ${CFG} (0600). Never copy it into a client profile,
a ticket, or a skill file.
SUMMARY
