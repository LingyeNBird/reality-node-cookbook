# Reality node cookbook

A portable, generic runbook for standing up a sing-box **VLESS+Reality** node on a remote
VPS and handing back a working Clash/mihomo profile — driven through an Orca terminal.

Everything here is placeholder-based. No host, port, domain, key or path from any real
deployment is baked in; fill them in for the task at hand.

Code blocks are labelled: **`[SERVER]` = type it into the Orca terminal session, as root; `[LOCAL]` = run it on your own machine.** Every `[SERVER]` block is guarded on `ORCA=yes` and does nothing without that marker, so pasting it into the wrong shell is a no-op.

## Contents

```
SKILL.md                              the procedure, with the pitfalls
README.md                             this file: ordered commands
scripts/orca_tty.py                   drive an Orca terminal; only handles it created itself
scripts/ssh_harden.sh                 staged SSH hardening: key install, port move, password off
scripts/sni_check_on_host.sh          screen AND prove reachability from the node — the decision
scripts/sni_screen.py                 optional local pre-filter (DoH + ASN + TLS probe); decides nothing
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
| `<NEW_SSH_PORT>` | SSH port to move to (Stage 0 only) |
| `<PUBKEY_FILE>` | local path to the `.pub` file being installed |
| `<LOCAL_KEY_PATH>` | local path to the encrypted private key |
| `<LOCAL_ARTIFACT_DIR>` | agreed directory **outside any repo** holding the key and the profile |
| `<SNI>` | the cover domain (`server_name` and handshake target) |
| `<NODE_NAME>` | display name in the client profile |
| `<UUID>` / `<PUBLIC_KEY>` / `<SHORT_ID>` | client credentials, printed by `node_setup.sh` |
| `<PORT>` | node's listen port (443 unless taken) |

## Before anything: ask for the inputs

The run below starts from information only the user has. Ask for all of it in one batch
before running a single command — one round trip is cheaper than a wrong host or a lockout.

| Need | Why it cannot be inferred |
|---|---|
| server address | several hosts are usually in play; "the server" is ambiguous |
| SSH port | may already have been moved off 22 |
| how to authenticate | key path with a passphrase the user types, or still password-only |
| whether SSH must be hardened, and **which new port** | their decision; it lands in their client config and firewall |
| cover-site constraints | region, things to avoid, or "you pick" |
| where local artifacts go | the key and the profile are credentials; they must not land in a repository |
| client and delivery | which client, and local file or hosted subscription |

**Forbidden — do not discover the target by enumeration.** Never read `~/.ssh/`
(`known_hosts`, `known_hosts.old`, `config`, keys), shell history, cloud CLI inventories,
or any `*config*` directory to work out which server, port or credential to use.
`known_hosts` is an inventory of every host the user has ever connected to, non-standard
ports included: reading it is a leak, not research. And never then probe the hosts you
found that way "to see which one is up". "Configure the server" without a name is a
question, not a puzzle.

## Ordered run

### 0. Get a shell on the node

```bash
# [LOCAL] your machine — these calls only drive the remote session
python scripts/orca_tty.py list
python scripts/orca_tty.py create --title "node" \
  --command 'ssh -o PreferredAuthentications=publickey -o IdentitiesOnly=yes -o ServerAliveInterval=15 -p <SSH_PORT> -i "<LOCAL_KEY_PATH>" root@<SERVER_IP>'
```

**Then stop** and tell the user to type the credential, and when they are in. Their typing
time is unbounded.

```bash
# [LOCAL] next turn, once they confirm — one check, 20s (not a deadline for them)
python scripts/orca_tty.py wait-prompt --terminal <HANDLE> --pattern ':~#\s*$' --timeout 20
```

A miss means they are not in yet: say so and end the turn again — do not extend or loop.

Ask the user not to toggle TUN / system proxy while the session is in use: an
interactive SSH session over a TUN interface dies the moment TUN goes off.

`orca_tty.py` enforces a **scope fence**. Orca's terminal listing is worktree-wide and
includes previews of every tab, including the agent's own; the tool therefore records the
handles it creates (`~/.orca-tty/created.json`), shows only those in `list`, and refuses
to read or write any other terminal — with no override flag. Do not bypass it by calling
`orca terminal read` / `orca terminal send` directly.

#### 0.1 Harden SSH access (only if the host is not there yet)

If the host still accepts a password, or SSH sits on the default port, fix that first —
everything below depends on a login you cannot be locked out of.

```bash
# [SERVER] inside the Orca terminal session, as root
[ "${ORCA:-}" = yes ] || { echo "refusing: ORCA != yes — run this inside the Orca session" >&2; false; } && {
bash /root/ssh_harden.sh status                    # effective policy + which file wins
bash /root/ssh_harden.sh preflight                 # the traps that apply to this host
echo <base64-of-pubkey> | base64 -d > /root/incoming.pub
bash /root/ssh_harden.sh install-key - < /root/incoming.pub
#   -> [LOCAL] prove a key-only login from OUTSIDE on the current port
bash /root/ssh_harden.sh stage-port <NEW_SSH_PORT> # old + new both listening
#   -> [LOCAL] prove a login from OUTSIDE on the NEW port: this is the gate
bash /root/ssh_harden.sh converge-port <NEW_SSH_PORT>
bash /root/ssh_harden.sh disable-password
}
```

Do not converge the port on the strength of a listening socket — a fresh login from
outside on the new port is the only acceptable proof. `SKILL.md` §2 explains the two
precedence traps this handles: drop-ins cannot override the main file above `Include`, and
a socket-activated sshd ignores `Port` entirely (`ListenStream` on `ssh.socket` owns it).

**Ask the user which port to use before running `stage-port`.** It is not the assistant's
call: the value has to go into their client config and their provider's firewall. Describe
what makes a good pick (above 1024, outside the host's ephemeral range from
`cat /proc/sys/net/ipv4/ip_local_port_range`, not one of the well-known alternate ports
scanners hit first) and wait.

Both port commands refuse a port that is already bound — checked with `ss` and a real bind
attempt — and `converge-port` snapshots the previous configuration, verifies the new port
is actually listening, and rolls back when it is not.

### 1. Pick the cover site

Candidates come from **you**, not from the user: §0 supplies the constraints (region, what
to avoid, or "you pick"). Screen them **on the node** — one probe answers both "usable as a
cover" and "reachable from here", and only the node can answer the second.

```bash
# [SERVER] screen and prove reachability at the same time — this is the decision
# (land the list in /root first, the same way as any other file)
[ "${ORCA:-}" = yes ] && bash /root/sni_check_on_host.sh --file /root/candidates.txt
```

Requirements: TLS 1.3 + X25519 + ALPN h2 + a valid chain, no Cloudflare (ideally no CDN at
all), a real low-profile **company** site — never `.gov` / `.edu` / `.mil` or a public
institution — and reachable from the node.

A local pre-filter is optional, for long lists, and only after §1's gate; it decides nothing:

```bash
# [LOCAL] optional triage; its verdict says nothing about the node
python scripts/sni_screen.py --file candidates.txt
```

### 2. Provision the node

```bash
# [SERVER] inside the Orca terminal — land node_setup.sh in /root first (SKILL.md §1)
[ "${ORCA:-}" = yes ] && SNI=<SNI> INSTALL=1 bash /root/node_setup.sh
```

Prints the six client values (public key, uuid, short id, server_name, port) and leaves
the private key at `/etc/<name>/config.json` mode 0600.

Swapping the cover site later is the same command with a new `SNI` — secrets are reused:

```bash
# [SERVER] inside the Orca terminal — same script, secrets are preserved
[ "${ORCA:-}" = yes ] && SNI=<NEW_SNI> bash /root/node_setup.sh
```

### 3. Verify from outside

```bash
# [LOCAL] both probes run from your machine, outside the node
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
# [LOCAL] your machine
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
