#!/usr/bin/env bash
# Screen Reality cover-site candidates FROM THE NODE, and decide in one pass.
#
# One probe here answers both questions that matter:
#
#   * is the host usable as a cover — TLS 1.3, X25519, ALPN h2, a valid chain, not
#     behind Cloudflare?
#   * can this node actually reach it? Reality relays every unauthenticated handshake to
#     this host, so a target the node cannot reach makes the node dead for every client.
#
# Screening from your own machine answers only the first question, and it answers it
# about your network. That is why this script is the decision, not a confirmation step.
#
#   bash sni_check_on_host.sh example.org example.net
#   bash sni_check_on_host.sh --file candidates.txt
#   bash sni_check_on_host.sh --file candidates.txt --jobs 8
#
# Exit status: 0 if at least one candidate passed.
set -uo pipefail

JOBS="${JOBS:-6}"
TCP_TIMEOUT="${TCP_TIMEOUT:-8}"
TLS_TIMEOUT="${TLS_TIMEOUT:-15}"

# Cloudflare's published IPv4 ranges: a cover site must not sit behind them.
CF_V4="173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 \
108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 \
162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22"

usage() {
  cat <<'EOF'
Screen cover-site candidates from this node and decide in one pass.

  sni_check_on_host.sh <domain> [<domain> ...]
  sni_check_on_host.sh --file <list> [--jobs N]

A line in the list may carry a # comment. A candidate passes only when it resolves, is
not in a Cloudflare range, accepts TCP/443 from this node, and completes a TLS 1.3
handshake with X25519 + ALPN h2 and a valid chain.
EOF
}

DOMAINS=()
FILE=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --file)  FILE="${2:-}"; shift 2 ;;
    --jobs)  JOBS="${2:-6}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    -*)      printf 'unknown option: %s\n' "$1" >&2; exit 2 ;;
    *)       DOMAINS+=("$1"); shift ;;
  esac
done

if [ -n "$FILE" ]; then
  [ -r "$FILE" ] || { printf 'cannot read %s\n' "$FILE" >&2; exit 2; }
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%%#*}"
    line="$(printf '%s' "$line" | tr -d '[:space:]')"
    [ -n "$line" ] && DOMAINS+=("$line")
  done < "$FILE"
fi

if [ "${#DOMAINS[@]}" -eq 0 ]; then
  usage >&2
  exit 2
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

is_cloudflare() {
  command -v python3 >/dev/null 2>&1 || return 1
  python3 - "$1" "$CF_V4" <<'PY'
import ipaddress, sys
ip = ipaddress.ip_address(sys.argv[1])
sys.exit(0 if any(ip in ipaddress.ip_network(n) for n in sys.argv[2].split()) else 1)
PY
}

probe() {  # <domain> <outfile>
  local d="$1" out="$2" v4 ips bad="" text alpn verify subject proto ip
  {
    v4=$(getent ahostsv4 "$d" 2>/dev/null | awk '{print $1}' | sort -u | head -2 | paste -sd' ' -)
    ips="${v4:-$(getent hosts "$d" 2>/dev/null | awk '{print $1}' | head -1)}"
    if [ -z "$ips" ]; then
      echo "ip=NONE verdict=FAIL does-not-resolve"
      return
    fi
    echo "ip=$(printf '%s' "$ips" | tr ' ' ',')"

    for ip in $v4; do
      if is_cloudflare "$ip"; then
        echo "verdict=FAIL cloudflare-range($ip)"
        return
      fi
    done

    if ! timeout "$TCP_TIMEOUT" bash -c "cat < /dev/null > /dev/tcp/${d}/443" 2>/dev/null; then
      echo "verdict=FAIL tcp-443-unreachable-from-this-node"
      return
    fi

    text=$(echo | timeout "$TLS_TIMEOUT" openssl s_client -connect "${d}:443" \
           -servername "$d" -tls1_3 -groups X25519 -alpn h2 2>&1)
    proto=$(grep -m1 -oa 'Protocol *: *TLSv1\.3' <<<"$text" || true)
    alpn=$(sed -n 's/^ *ALPN protocol: *//p' <<<"$text" | head -1)
    verify=$(sed -n 's/^ *Verify return code: *//p' <<<"$text" | head -1)
    subject=$(sed -n 's/^ *subject=//p' <<<"$text" | head -1)

    [ -n "$proto" ] || bad="$bad no-tls1.3"
    [ "$alpn" = "h2" ] || bad="$bad alpn=${alpn:-none}"
    case "$verify" in 0*) ;; *) bad="$bad verify=${verify:-none}";; esac
    [ -n "$subject" ] || bad="$bad no-cert"

    if [ -z "$bad" ]; then
      echo "verdict=PASS subject=${subject}"
    else
      echo "verdict=FAIL${bad}"
    fi
  } > "$out" 2>&1
}

echo "screening ${#DOMAINS[@]} candidate(s) from $(hostname), ${JOBS} at a time"
echo

i=0
for d in "${DOMAINS[@]}"; do
  probe "$d" "$WORK/$i.out" &
  i=$((i + 1))
  while [ "$(jobs -rp | wc -l)" -ge "$JOBS" ]; do sleep 0.2; done
done
wait

pass=0
fail=0
i=0
for d in "${DOMAINS[@]}"; do
  line=$(tr '\n' ' ' < "$WORK/$i.out")
  if printf '%s' "$line" | grep -q 'verdict=PASS'; then
    pass=$((pass + 1))
    printf '  PASS  %-34s %s\n' "$d" "${line#*verdict=PASS }"
  else
    fail=$((fail + 1))
    printf '  FAIL  %-34s %s\n' "$d" "${line#*verdict=FAIL}"
  fi
  i=$((i + 1))
done

echo
echo "passed ${pass}, failed ${fail}"
echo
if [ "$pass" -gt 0 ]; then
  echo "Every PASS above is reachable from this node and usable as a cover."
  echo "The cover site is the user's decision: present the PASS list and stop."
else
  echo "No candidate passed. Generate a different set — do not relax the criteria."
fi

[ "$pass" -gt 0 ]
