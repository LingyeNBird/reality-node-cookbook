---
name: singbox-reality-node-runbook
description: End-to-end runbook for taking a bare VPS to a working sing-box VLESS+Reality node through an Orca terminal — staged SSH access hardening (key install, port move, password shutdown), Orca session mechanics, port and non-Cloudflare SNI selection, secret generation, a hardened systemd unit, camouflage and end-to-end verification, client profile generation, and the failure modes that actually happen in production.
---

# sing-box VLESS+Reality node runbook

Portable procedure. Every host, port, domain, key, and path appears as a placeholder — fill them in from the current task, never hard-code one task's values into this folder.

Scripts referenced below live in `scripts/`, templates in `templates/`. Read `README.md` for the ordered command sequence.

## 0. What you are producing

1. A remote VPS running sing-box with a VLESS+Reality inbound on TCP/443.
2. An importable Clash/mihomo profile for the client.
3. Evidence that both work: camouflage probe, real-client egress, restart survival.

## 1. Preconditions, and Stage 0 when they are not met

- Confirm which server the user actually means before touching anything. Several hosts may be open in several tabs.
- SSH access must work with a **passphrase-protected key**, and the passphrase stays with the user (a password manager). Never write it to disk, never echo it.
- If the host is still on password auth, or the user wants SSH moved to a high port, do that first with `scripts/ssh_harden.sh`. It is staged so that no step can lock you out:

```bash
bash scripts/ssh_harden.sh status                    # effective policy + which file wins
bash scripts/ssh_harden.sh preflight                 # what this host actually reads
bash scripts/ssh_harden.sh install-key <pubkey.pub>  # append + fix modes
#   -> prove a key-only login from OUTSIDE on the current port
bash scripts/ssh_harden.sh stage-port <new-port>     # old + new both listening
#   -> prove a login from OUTSIDE on the NEW port: this is the gate
bash scripts/ssh_harden.sh converge-port <new-port>  # new port only
bash scripts/ssh_harden.sh disable-password          # then prove password is refused
```

Two traps it encodes, both of which make a naive fix silently do nothing:

- **A drop-in cannot override the main file above `Include`.** OpenSSH keeps the FIRST obtained value and `Include` sits partway down `sshd_config`, while vendor images often set live directives above it. `ssh_harden.sh status` prints which source wins for every keyword, and the setters edit that source rather than adding another file that loses.
- **Recent Ubuntu is socket-activated** (`ssh.socket`, `Accept=no`): a `Port` line in `sshd_config` is inert because `ListenStream` on the socket unit owns the port. Change the unit, `daemon-reload`, then restart **both** `ssh.socket` and `ssh.service` so sshd inherits the new fds.

Never converge the port before a fresh login on the new port has succeeded from outside. An existing session is not proof, and neither is a listening socket.

**Stop at the port step and ask the user which port to use.** It is their decision: the value ends up in their client config, their provider's firewall rules and their notes. Do not invent one and do not "just pick a random high port". Say what makes a good choice (anything from 1024 up; avoid the host's ephemeral range, which is `cat /proc/sys/net/ipv4/ip_local_port_range`; avoid the well-known alternate ports that scanners try first), then wait for an answer before running `stage-port`.

`stage-port` and `converge-port` both refuse a port that is already bound — checked twice, with `ss` and an actual bind attempt — and `converge-port` snapshots the old configuration, verifies the new port really listens, and rolls back if it does not. Converging is the one step that removes the old port, so a failed bind there would otherwise leave no listener at all.

## 2. Driving the session through Orca

Use `scripts/orca_tty.py` rather than raw `orca` calls; it encodes the pitfalls.

```bash
python scripts/orca_tty.py list
python scripts/orca_tty.py create --title "node work" \
  --command 'ssh -o PreferredAuthentications=publickey -o IdentitiesOnly=yes -o ServerAliveInterval=15 -p <SSH_PORT> -i "<LOCAL_KEY_PATH>" root@<SERVER_IP>'
python scripts/orca_tty.py wait-prompt --terminal <HANDLE> --pattern 'root@.*:~#' --timeout 150
python scripts/orca_tty.py run-script --terminal <HANDLE> --file scripts/node_setup.sh
```

Hard rules, learned the hard way:

- **Resolve the CLI once per session.** `ORCA_CLI_COMMAND` → `orca-dev` (dev checkout) → `orca-ide` (Linux, outside an Orca terminal — bare `orca` there is the GNOME screen reader) → `orca`.
- **Never use `terminal wait --for tui-idle`.** Commands routinely finish before the wait starts, and the wait then hangs. Read with a cursor instead.
- **Read before you write.** `terminal read --cursor <n>` returns only new lines; keep the cursor.
- **Send multi-line anything as base64.** `echo <b64> | base64 -d | bash`. Heredocs and nested quotes through `terminal send` break in ways that are hard to see.
- **Poll for the shell prompt after `ssh`.** The user types the passphrase by hand; the assistant cannot supply it. Poll for `:~#`, then continue in the same turn.
- **`terminal_handle_stale` means the Orca app restarted** and took the session with it. Re-list terminals, create a new one, ask the user to authenticate again. Do not assume the old session still runs commands.
- **Ask the user not to toggle TUN / system proxy while you work.** An interactive SSH session routed over a TUN interface dies the moment TUN is switched off, mid-command, and the change you were applying may not have landed.
- **Never print the private key.** Generate secrets inside the remote script, keep them in shell variables, echo only public values (public key, uuid, short_id).

## 3. Recon (read-only)

```bash
. /etc/os-release; echo "$PRETTY_NAME $(uname -m)"; nproc; free -m | head -2; df -h / | tail -1
command -v sing-box && sing-box version || echo NO_SING_BOX
systemctl list-units --type=service --all --no-pager | grep -iE 'sing|xray|v2ray|reality'
ss -lntup
ufw status verbose
curl -sS -o /dev/null -w 'github=%{http_code}\n' --max-time 15 https://api.github.com/
```

Leave any pre-existing proxy daemon strictly alone: different unit name, different port.

## 4. Port and SNI

**Port: 443.** Reality's whole value is that the IP genuinely serves a real TLS site there. A high port turns the camouflage into "some site on an odd port". Only move if 443 is occupied.

**SNI target** — all of these must hold:

- TLS 1.3, X25519 key exchange, ALPN `h2`, certificate chain valid for that hostname.
- **Not Cloudflare**, and ideally not any CDN/WAF: a plain origin (shared hosting, small VPS, regional ISP) is the best camouflage.
- A real, stable, low-profile company site, ideally in the same region as the node.
- **Reachable from the node itself.** Reality relays every unauthenticated handshake to this host; if the node cannot reach it, the node is dead for every client too.

Screen candidates locally, then verify on the node:

```bash
python scripts/sni_screen.py --file candidates.txt          # runs on your machine
# copy the survivors over, then ON THE NODE:
bash scripts/sni_check_on_host.sh <candidate> [<candidate> ...]
```

`scripts/sni_screen.py` encodes two traps that silently produce garbage results:

- **A local Clash/proxy in fake-ip mode poisons plain DNS.** Every lookup returns the fake range (e.g. `198.18.0.0/15`), so an "is it Cloudflare" check passes everything. The script resolves over DoH and connects to the resolved IP with an explicit SNI, bypassing the local resolver.
- **Cloudflare's published range list is not exhaustive.** Some Cloudflare-fronted space sits outside it, and some platform ranges are announced by unrelated ASNs. The script cross-checks the ASN holder and flags CDN/WAF owners explicitly.

Also expect: a mismatched SNI returns the upstream host's default vhost certificate (normal on shared hosting), and a site that merely speaks TLS 1.3 but not h2 is unusable.

## 5. Install sing-box

```bash
REL=$(curl -sS --max-time 25 https://api.github.com/repos/SagerNet/sing-box/releases/latest)
VER=$(echo "$REL" | grep -oP '"tag_name":\s*"\K[^"]+' | head -1)
curl -fsSL -o /tmp/sb.tgz "https://github.com/SagerNet/sing-box/releases/download/$VER/sing-box-${VER#v}-linux-amd64.tar.gz"
sha256sum /tmp/sb.tgz
tar xzf /tmp/sb.tgz -C /tmp && install -m0755 /tmp/sing-box-*/sing-box /usr/local/bin/sing-box
sing-box version
```

Report the version and the tarball hash so the artifact is auditable.

## 6. Secrets, config, unit

Use `scripts/node_setup.sh`. It is idempotent and SNI-swappable: on an existing config it **reuses** the private key, uuid and short_id and only changes `server_name` / `handshake.server`, which is exactly what a target swap needs.

```bash
SNI=<domain> PORT=443 bash scripts/node_setup.sh
```

What it enforces:

- `sing-box check` before every restart; abort on failure.
- A dedicated system account, config `0600`, so the private key is not world-readable.
- `AmbientCapabilities=CAP_NET_BIND_SERVICE` to bind :443 without root.
- `RestrictAddressFamilies` includes `AF_NETLINK` — sing-box aborts at startup without it.
- A backup of the previous config on every change.

The 1.14.x config shape (field names have moved across releases — always let `sing-box check` arbitrate):

```json
{"inbounds":[{"type":"vless","listen":"::","listen_port":443,
  "users":[{"uuid":"<UUID>","flow":"xtls-rprx-vision"}],
  "tls":{"enabled":true,"server_name":"<SNI>",
         "reality":{"enabled":true,
                    "handshake":{"server":"<SNI>","server_port":443},
                    "private_key":"<PRIVATE_KEY>","short_id":["<SHORT_ID>"]}}}],
 "outbounds":[{"type":"direct"}]}
```

## 7. Verify — three independent proofs

```bash
python scripts/node_verify.py --host <SERVER_IP> --port 443 --sni <SNI> --repeat 3
python scripts/client_e2e.py --sing-box <path-to-sing-box> \
    --server <SERVER_IP> --port 443 --uuid <UUID> --sni <SNI> --pbk <PUBLIC_KEY> --sid <SHORT_ID>
systemctl restart <unit>   # then re-run the camouflage probe
```

1. **Camouflage / relay** — a plain TLS client presenting the configured SNI must receive the **real certificate of that site**, because unauthenticated handshakes are relayed to the target. This is also the cheapest health check.
2. **Real end-to-end** — a genuine client must egress as the node's IP via both HTTP and SOCKS5, and differently from a direct control.
3. **Restart survival** — a node that only works until the first restart is not done.

`scripts/node_verify.py` distinguishes "server sent zero bytes" (Reality could not reach its target) from "certificate mismatch" (wrong SNI or wrong target), which is the difference between a server fault and a client fault.

## 8. Client profile

Copy the user's own template and change **only** the node block: `server`, `port`, `uuid`, `servername`, `reality-opts`. Keep their DNS, TUN, groups and rules byte-identical — they chose those.

```yaml
proxies:
  - name: "<NODE_NAME>"
    type: vless
    server: <SERVER_IP>
    port: 443
    uuid: <UUID>
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    servername: <SNI>
    client-fingerprint: chrome
    reality-opts:
      public-key: <PUBLIC_KEY>
      short-id: <SHORT_ID>
```

Even when the user says they will import and test it themselves: parse the YAML, assert the node fields equal the generated values, and assert the template's previous node values are **all gone** (old IP, old uuid, old SNI, placeholder `xxx`). A half-replaced template is the most common defect. Remember the proxy name appears twice — in `proxies` and in every group's member list.

## 9. Failure modes

**Node suddenly unreachable, but the port is open.** TCP connects succeed while every TLS handshake dies (`ConnectionReset`, `unexpected EOF`, or "handshake read 0 bytes"), from unrelated networks too.

```bash
journalctl -u <unit> -n 40 --no-pager | grep -i 'failed to dial dest'
curl -sS -o /dev/null -w '%{http_code} %{time_total}\n' --max-time 12 https://<SNI>/
```

`REALITY: failed to dial dest: dial tcp <ip>:443: i/o timeout` plus a timing-out curl **from the node** means the target stopped being reachable from that server — common when a small shared host rate-limits or blocks the node's IP. Reality relays all probe traffic to the target, so the target sees sustained connections from one address. Check general egress (`curl https://api.github.com/`) and `uptime` first to rule out a wider outage, then swap the target.

Contrast with the healthy case: the journal shows `REALITY: processed invalid connection`, the target answers `200` from the node, and a plain SNI probe returns the target's real certificate. "Invalid connection" is the normal log line for unauthenticated probes, not a fault.

**Client profile not actually in use.** Before blaming the server, check what the client runtime really loaded (`<clash-runtime-dir>/config.yaml`): a profile that was imported but not selected leaves the old node active. A client still sending the previous SNI also fails — after any SNI change the profile must be re-imported.

**Distinguish the paths.** Direct and proxied probes to the same node answer different questions. Test both before concluding: if both fail the same way it is the server, if only one fails it is that path.

## 10. Boundaries to state plainly

- Reality makes the node undiscoverable; it does **not** prevent sharing once the profile leaks. One UUID means a leak forces every device to rotate; per-device UUIDs allow revoking one.
- The client profile is a credential. Treat it as a secret.
- A small SNI target can be blocked by its own host; keep two or three pre-verified spares so a swap takes seconds.

## 11. Hygiene

- No credentials, host addresses, or chosen domains in this folder or in any skill file.
- Back up the server config before each change; keep the previous one until the new state is verified.
- Delete throwaway test helpers and temporary client downloads when done.
