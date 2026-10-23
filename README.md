# Reality node cookbook

A portable, generic runbook for standing up a sing-box **VLESS+Reality** node on a remote
VPS and handing back a working Clash/mihomo profile — driven through an Orca terminal.

Everything here is placeholder-based. No host, port, domain, key or path from any real
deployment is baked in; fill them in for the task at hand.

## Contents

```
SKILL.md                              the procedure, with the pitfalls
README.md                             this file: ordered commands
scripts/orca_tty.py                   drive an Orca terminal: create/read/send/run-script
scripts/sni_screen.py                 screen SNI candidates locally (DoH + ASN + TLS probe)
scripts/sni_check_on_host.sh          verify candidates FROM THE NODE (decisive)
scripts/node_setup.sh                 install/configure/restart the node (idempotent, SNI-swappable)
scripts/node_verify.py                probe the node from outside (camouflage + health)
scripts/client_e2e.py                 run a real client and compare three egress paths
templates/server-config.json          sing-box inbound config skeleton
templates/singbox-reality.service     hardened systemd unit
templates/mihomo-proxy-block.yaml     client proxy block
```

## Placeholders

| Token | Meaning |
|---|---|
| `<SERVER_IP>` | node's public IPv4 |
| `<SSH_PORT>` | node's SSH port |
| `<LOCAL_KEY_PATH>` | local path to the encrypted private key |
| `<SNI>` | the cover domain (`server_name` and handshake target) |
| `<NODE_NAME>` | display name in the client profile |
| `<UUID>` / `<PUBLIC_KEY>` / `<SHORT_ID>` | client credentials, printed by `node_setup.sh` |
| `<PORT>` | node's listen port (443 unless taken) |

## Ordered run

### 0. Get a shell on the node

```bash
python scripts/orca_tty.py list
python scripts/orca_tty.py create --title "node" \
  --command 'ssh -o PreferredAuthentications=publickey -o IdentitiesOnly=yes -o ServerAliveInterval=15 -p <SSH_PORT> -i "<LOCAL_KEY_PATH>" root@<SERVER_IP>'
# the user types the key passphrase; wait for the remote prompt
python scripts/orca_tty.py wait-prompt --terminal <HANDLE> --pattern ':~#\s*$'
```

Ask the user not to toggle TUN / system proxy while the session is in use: an
interactive SSH session over a TUN interface dies the moment TUN goes off.

### 1. Pick the SNI target

```bash
# locally (uses DoH, so a fake-ip proxy cannot poison the answer)
python scripts/sni_screen.py --file candidates.txt

# on the node — the only check that actually predicts whether the node will work
bash scripts/sni_check_on_host.sh <candidate> [<candidate> ...]
```

Requirements: TLS 1.3 + X25519 + ALPN h2 + valid chain, no Cloudflare (ideally no CDN at
all), a real low-profile company site, and reachable from the node.

### 2. Provision the node

```bash
SNI=<SNI> INSTALL=1 bash scripts/node_setup.sh
```

Prints the six client values (public key, uuid, short id, server_name, port) and leaves
the private key at `/etc/<name>/config.json` mode 0600.

Swapping the cover site later is the same command with a new `SNI` — secrets are reused:

```bash
SNI=<NEW_SNI> bash scripts/node_setup.sh
```

### 3. Verify from outside

```bash
python scripts/node_verify.py --host <SERVER_IP> --sni <SNI> --repeat 3
python scripts/client_e2e.py --sing-box <path-to-sing-box> \
    --server <SERVER_IP> --uuid <UUID> --sni <SNI> --pbk <PUBLIC_KEY> --sid <SHORT_ID>
```

The first must show the cover site's real certificate (that is the camouflage working).
The second must show the two proxied paths agreeing with each other and differing from
the direct control.

### 4. Hand over the client profile

Start from the user's own profile, replace only the node block
(`templates/mihomo-proxy-block.yaml`), then assert the result:

```bash
python - <<'PY'
import yaml, sys
cfg = yaml.safe_load(open("<PROFILE_PATH>", encoding="utf-8"))
px = cfg["proxies"][0]
print(px)
# assert: server/port/uuid/servername/reality-opts equal the generated values,
# and none of the template's previous node values survive.
PY
```

## When it breaks

| Symptom | Check | Meaning |
|---|---|---|
| Port open, every handshake reset / 0 bytes | `journalctl -u <unit> \| grep 'failed to dial dest'` and `curl https://<SNI>/` **on the node** | the cover site stopped being reachable from the node — swap the target |
| Handshake fine, client still dead | the client's real runtime config | profile imported but not selected, or still sending the old SNI |
| Journal shows `REALITY: processed invalid connection` | — | normal for unauthenticated probes; not a fault |

## Notes

- Reality hides the node, it does not stop sharing: whoever holds the profile can use it.
  One UUID means a leak rotates every device.
- A small cover site can be blocked by its own host; keep two or three pre-verified
  spares so a swap is seconds, not a new screening round.
- Keep credentials out of this folder. It is meant to be reusable and shareable.

## Installing as a skill

Copy `SKILL.md` (and `scripts/`, `templates/`) into a skills directory, e.g.
`~/.omp/agent/skills/singbox-reality-node-runbook/`, so it is discovered like any other
skill. The folder is self-contained.
