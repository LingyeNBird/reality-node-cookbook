#!/usr/bin/env bash
# Verify candidate Reality targets FROM THE NODE.
#
# Run this on the server, not on the client. Reality relays every unauthenticated
# handshake to the configured target; a target the node cannot reach makes the node
# unusable for everybody, while the same target still looks fine from elsewhere.
# Local screening passing is therefore not sufficient.
#
#   bash sni_check_on_host.sh example.org example.net
#
# Exit status: 0 if at least one candidate passed, 1 otherwise.
set -uo pipefail

TCP_TIMEOUT="${TCP_TIMEOUT:-12}"
TLS_TIMEOUT="${TLS_TIMEOUT:-15}"
pass=0
fail=0

probe() {
  local d="$1" ips v4
  printf '%-34s ' "$d"

  v4=$(getent ahostsv4 "$d" 2>/dev/null | awk '{print $1}' | sort -u | head -2 | paste -sd, -)
  ips="${v4:-$(getent hosts "$d" 2>/dev/null | awk '{print $1}' | head -1)}"
  printf 'ip=%-22s ' "${ips:-NONE}"

  if [ -z "${ips}" ]; then
    echo "FAIL  (does not resolve)"
    return 1
  fi

  if ! timeout "${TCP_TIMEOUT}" bash -c "cat < /dev/null > /dev/tcp/${d}/443" 2>/dev/null; then
    echo "FAIL  tcp/443 unreachable from this node"
    return 1
  fi
  printf 'tcp=OK '

  local out proto alpn verify subject verdict
  out=$(echo | timeout "${TLS_TIMEOUT}" openssl s_client \
        -connect "${d}:443" -servername "$d" -tls1_3 -groups X25519 -alpn h2 2>&1)
  proto=$(grep -m1 -oa 'Protocol *: *TLSv1\.3' <<<"$out" || true)
  alpn=$(sed -n 's/^ *ALPN protocol: *//p' <<<"$out" | head -1)
  verify=$(sed -n 's/^ *Verify return code: *//p' <<<"$out" | head -1)
  subject=$(sed -n 's/^ *subject=//p' <<<"$out" | head -1)

  verdict=""
  [ -n "$proto" ] || verdict="$verdict no-tls1.3"
  [ "$alpn" = "h2" ] || verdict="$verdict alpn=${alpn:-none}"
  case "$verify" in 0*) ;; *) verdict="$verdict verify=${verify:-none}";; esac
  [ -n "$subject" ] || verdict="$verdict no-cert"

  if [ -z "$verdict" ]; then
    echo "PASS  alpn=h2 -> ${subject}"
    return 0
  fi
  echo "FAIL ${verdict}"
  return 1
}

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <domain> [<domain> ...]" >&2
  exit 2
fi

echo "candidate reachability from $(hostname) (this is the decisive check)"
echo
for d in "$@"; do
  if probe "$d"; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
  fi
done

echo
echo "passed ${pass}, failed ${fail}"
[ "$pass" -gt 0 ]
