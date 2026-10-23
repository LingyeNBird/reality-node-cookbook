---
name: singbox-reality-node-runbook
description: End-to-end runbook for taking a bare VPS to a working sing-box VLESS+Reality node through an Orca terminal — collecting the inputs from the user up front (never inferring them from the machine), staged SSH access hardening (key install, port move, password shutdown), Orca session mechanics, port and non-Cloudflare SNI selection, secret generation, a hardened systemd unit, camouflage and end-to-end verification, client profile generation, and the failure modes that actually happen in production.
---

# sing-box VLESS+Reality node runbook

Portable procedure. Every host, port, domain, key, and path appears as a placeholder — fill them in from the current task, never hard-code one task's values into this folder.

Scripts referenced below live in `scripts/`, templates in `templates/`. Read `README.md` for the ordered command sequence.

**What you are producing:** a remote VPS running sing-box VLESS+Reality on TCP/443, an importable Clash/mihomo profile, and the evidence that both work — camouflage probe, real-client egress, restart survival.

## Rules

These are not advice. Each one exists because ignoring it broke something.

Code blocks are labelled. **`[SERVER]` means: type it into the Orca terminal session opened in §1, as root — never into your own shell.** `[LOCAL]` means: run it on your own machine. A block that does both is split and labelled line by line.

Every `[SERVER]` block opens with an `ORCA=yes` guard and does nothing when the marker is unset, so a block pasted into the wrong shell — or a session that was never authenticated — is a no-op instead of a remote change. The guard is written so it fails **without** killing an interactive shell.

### Scope and consent

1. **MUST ask before acting.** Collect the six inputs in §0 first. MUST NOT infer the target from the machine.
2. **MUST NOT enumerate to discover anything.** No `~/.ssh` (any file), `known_hosts`, shell history, cloud CLI inventories, `*config*` directories, project `.env`. The same ban covers discovering the cover site and the client profile. MUST NOT probe hosts discovered that way.
3. **MUST agree where local artifacts go.** Before creating a key, a passphrase file or a profile, agree on a directory **outside every repository** (see *Local artifacts*). MUST NOT default to the CWD, `$TEMP`, or the repo.
4. **MUST stay in scope.** No firewall changes, no DNS changes, no edits to unrelated services or repositories, no "improvements" the task did not ask for.

### Session and terminal

5. **MUST have a shell before running anything.** A created terminal is not a session, and its buffer is not output.
6. **`create` is followed by a question, not a wait.** The credential is the user's, so the next action is to tell them where to type it and **end the turn**. MUST NOT block on a wait, MUST NOT poll in a loop, and MUST NOT start any other work — local screening, downloads or candidate generation included — while the login is pending.
   - **Confirm exactly once, after they say they are in.** Then call `wait-prompt --timeout 20` a single time to check the prompt is on screen. A miss means they are not in yet: say so and end the turn again. That timeout is **not a deadline for the user** — it bounds only how long we look at the screen after they told us they were done; their typing is unbounded. MUST NOT extend it or retry.
   - **The session MUST be marked, and every `[SERVER]` block MUST check the mark.** Once the prompt appears, `export ORCA=yes` MUST be present in that shell (`wait-prompt` does this by itself). Every subsequent block provided for that session MUST open with the `ORCA=yes` guard and MUST do nothing when it is unset. A block that cannot be guarded MUST NOT be provided at all.
7. **Credentials are the user's.** MUST NOT type or store a passphrase or password, MUST NOT assume it was entered, MUST NOT act while the screen still shows an auth prompt.
8. **MUST only touch terminals this tool created.** MUST NOT read or write any other handle — including the agent's own terminal — and MUST NOT bypass the fence with a direct `orca terminal read|send`.
9. **MUST land a script before invoking it,** and MUST NOT use `run-script` for a script that takes subcommands: it has no argument slot.
10. **MUST use bounded waits.** No `wait --for tui-idle`; every poll carries a timeout, and a timeout is a stop, not a retry loop.
11. **MUST say so when a privileged session is still open,** and close the ones that are finished.

### Order and gates

12. **Stage order is fixed.** MUST NOT enter stage N+1 before stage N's gate passes. Local work is a stage too.
13. **The port and the cover site are the user's decisions.** MUST stop and ask. MUST NOT pick a default, and MUST NOT "just choose a random high port".
14. **MUST NOT converge a port before a fresh login from outside succeeds on the new port.** A listening socket is not proof.
15. **MUST NOT disable password auth before a key login succeeds on the current port.**
16. **A failed gate is a stop.** MUST report it and wait; MUST NOT continue with a workaround that has not been agreed.

### Secrets and files

17. **MUST NOT print or transcribe the private key or the passphrase.** Echo public values only: public key, fingerprint, uuid, short id.
18. **The passphrase lives in exactly one file, and only until it is imported.** `scripts/ssh_keygen.sh` writes it `0600` in the agreed directory; delete that file once the user confirms it is in their password manager. MUST NOT persist it anywhere else — no shell history, no notes, no second copy, no transcript.
19. **MUST generate the key only in the agreed place** — ed25519 with `-a 100` — and MUST NOT overwrite an existing key. Report the public key and its fingerprint.
   - **The passphrase is generated by the assistant and handed over as a file**, never through the transcript: `scripts/ssh_keygen.sh --dir <artifact-dir>`. The strength floor lives in that script — 32 random bytes (256 bits) by default, and anything under 24 bytes (192 bits) is refused rather than accepted. MUST NOT hand-write a "strong enough looking" string.
   - The passphrase file is mode `0600`, named so it is obviously temporary, and its *path* is reported — never its contents, in output, logs or chat. Tell the user to move it into their password manager and delete the file (rule 18).
20. **MUST restrict local permissions.** POSIX `0600` for files, `0700` for the directory; on Windows `icacls` down to owner and SYSTEM, inheritance removed.
21. **The client profile is a credential.** MUST deliver it by path. MUST NOT paste it into chat, MUST NOT commit it, MUST NOT write it inside a repository.
22. **MUST keep this package placeholder-only.** MUST NOT bake any deployment's address, port, domain, key, path or fingerprint into it.

### Change safety

23. **MUST back up before every mutation** — `sshd_config`, the sing-box config, the unit — and keep the backup until the new state is verified.
24. **MUST be idempotent.** Re-running MUST NOT rotate secrets; swapping the cover site MUST keep uuid, private key and short id.
25. **MUST leave pre-existing services untouched.** Distinct unit name, distinct port, no edits to anything this run did not create.
26. **MUST validate before every restart** (`sshd -t`, `sing-box check`). On failure: stop, leave the service running as it was.

### Verification and honesty

27. **MUST NOT trust local network facts.** Local DNS may be fake-ip and local reachability says nothing about the node: screening happens locally, acceptance happens on the node.
28. **MUST verify before claiming done** — the three proofs in §7 — and MUST name which checks ran and which did not. MUST NOT imply coverage that was not exercised.
29. **MUST change only the node block** of the user's client template, assert the result afterwards, and remember the proxy name appears twice.
30. **MUST NOT operate the user's client for them** when they said they would import it themselves.
31. **MUST distinguish observed from inferred,** and MUST NOT present a hypothesis as a result.

### Handover

32. **MUST hand over inventory and rollback** — paths, permissions, unit, service account, hashes, and the exact undo commands — and MUST say whether the rollback path was exercised.
33. **MUST delete throwaway artifacts** (downloads, scratch scripts, test terminals) and state what was left behind.

## Local artifacts

Everything this flow produces on the **client** machine is a key or a credential. It lives in one agreed directory outside every repository — never in the working tree, never in `$TEMP`.

```
<LOCAL_ARTIFACT_DIR>/          # agreed with the user, 0700
├── id_ed25519                # private key, 0600
├── id_ed25519.pub
├── <profile>.yaml            # client profile: carries the node uuid / public key / short id
└── id_ed25519.passphrase.txt # generated by ssh_keygen.sh, 0600; temporary, deleted after import
```

Generate both the key and its passphrase with `scripts/ssh_keygen.sh --dir <LOCAL_ARTIFACT_DIR>`: it produces 32 random bytes (256 bits) of passphrase by default, refuses anything below 24 bytes (192 bits), verifies that the key really is encrypted, and prints only the public key, the fingerprint and the file paths.

| Platform | Locking it down |
|---|---|
| POSIX | `mkdir -m 0700 <DIR> && chmod 600 <DIR>/*` |
| Windows | `icacls "<DIR>" /inheritance:r /grant:r "%USERNAME%:(OI)(CI)F" "SYSTEM:(OI)(CI)F"` |

The private key must also satisfy the SSH client's own permission check, or `ssh` refuses to use it (`UNPROTECTED PRIVATE KEY FILE` on Windows). Prove it with a real login rather than assuming.

If the user names a path **inside** a repository, say so and propose another one: the profile carries the node credentials and repositories get pushed. A defensive `.gitignore` entry is not a substitute for keeping them out.

## Stage gates

You may not enter a stage until the previous gate has passed. Each gate is evidence, not intent.

| Stage | Entering requires | Gate — all must pass before the next stage |
|---|---|---|
| 0 inputs | — | the six answers, from the user |
| 1 session | address, current SSH port, credential mode | `:~#` observed on a handle this tool created |
| 2 hardening (only if needed) | an authenticated session | key login works on the current port; **then** on the new port; password refused while the key still works |
| 3 recon | session | inventory read, 443 free, egress OK, pre-existing daemons catalogued and left alone |
| 4 port + cover site | recon | port chosen by the user; every candidate verified **on the node**; one chosen by the user |
| 5 install | chosen cover site reachable from the node | version and tarball hash printed, binary runs |
| 6 config + unit | install | `sing-box check` OK, unit active, listener on the chosen port |
| 7 verify | service running | camouflage proof, end-to-end proof, restart survival |
| 8 profile | verify | YAML parses, node fields equal the generated values, no template leftovers |
| 9 handover | profile | inventory + rollback delivered, unverified items named |

## 0. Ask for the inputs first

The first action is a question, not an exploration. Every later step is wrong if the target is wrong, and a wrong target costs someone a server.

Collect all of it in **one** batch — do not drip-feed questions:

| Need | Why it must come from the user |
|---|---|
| server address (IP or hostname) | several hosts are usually in play; "the server" is ambiguous |
| SSH port | may already have been moved off 22 |
| how to authenticate | key path plus a passphrase **the user types**, or still password-only |
| whether SSH must be hardened first, and **which new port** | their call: it ends up in their client config, their firewall, their notes |
| cover-site constraints | region, things to avoid, or "you pick" |
| client and delivery | which client, and whether the profile is a local file or a hosted subscription |

If any of these is missing, stop and ask. One round trip is cheaper than a wrong host, a wrong port, or a lockout.

### Forbidden: inferring the target from the machine

Never work out which server, port, or credential to use by reading the environment. Specifically forbidden, with no "just to help" exception:

- `~/.ssh/` in any form — `known_hosts`, `known_hosts.old`, `config`, keys, `authorized_keys`;
- shell history, cloud CLI inventories (`~/.aws`, `gcloud` configs), password-manager exports;
- any `*config*` directory, project `.env`, CI secrets;
- probe/scan hosts you discovered that way "to see which one is up".

`known_hosts` is an inventory of every host the user has ever connected to, non-standard ports included. Reading it is a data leak, not research, and it is exactly the shortcut that turns "configure the server" into "enumerate the user's infrastructure".

"Configure the server" with no server named is a question to ask, not a puzzle to solve. The same applies to the port and to the cover site: those are decisions, not defaults.

## 1. Open a session through Orca

Everything after this runs **on the server**, so the shell comes first — including the SSH hardening in §2. Without a live session there is nothing to execute.

Use `scripts/orca_tty.py` rather than raw `orca` calls; it encodes the pitfalls.

### Generate the key first, if there is none

The `ssh` command below needs a key. Create it — together with a passphrase that is generated, stored and never printed:

```bash
# [LOCAL] your machine — writes key + .pub + passphrase file; nothing secret reaches stdout
bash scripts/ssh_keygen.sh --dir <LOCAL_ARTIFACT_DIR>
```

Report the public key, the fingerprint and the passphrase file path — never the file's contents. The script refuses anything below 24 random bytes (192 bits) and verifies that the key really is encrypted before reporting success.

```bash
# [LOCAL] your machine — this only drives the remote session
python scripts/orca_tty.py list
python scripts/orca_tty.py create --title "node work" \
  --command 'ssh -o PreferredAuthentications=publickey -o IdentitiesOnly=yes -o ServerAliveInterval=15 -p <CURRENT_SSH_PORT> -i "<LOCAL_KEY_PATH>" root@<SERVER_IP>'
```

**Then stop.** Say "type your credential in that terminal and tell me when you are in", and end the turn. Their typing time is unbounded — there is nothing to wait on.

```bash
# [LOCAL] next turn, once they say they are in — one check, 20s
python scripts/orca_tty.py wait-prompt --terminal <HANDLE> --pattern 'root@.*:~#' --timeout 20
```

A miss means they are not in yet: say so, end the turn again. Do not extend the timeout, do not loop.

`-p` is the **current** port. If the host is still on password auth the same command works — the user types the password at the prompt. Moving the port is §2, not here.

### Getting a script onto the remote

Two shapes. Picking the wrong one is why a parameterised script appears to do nothing:

| Script | How to run it |
|---|---|
| no arguments, does a whole task | `run-script --file <path>` — base64-encodes it, pipes it into `bash` |
| takes arguments or subcommands | `send-script --file <path>` to land it, then `send --text 'bash /root/<name> preflight'` |

`run-script` has no argument slot: it feeds the file to `bash` on stdin, so `ssh_harden.sh preflight` must be a separate `send`. Files that start life on the client — a public key, a config — travel the same way:

```bash
# [LOCAL] the call is local; it types the file into the remote shell
python scripts/orca_tty.py send --terminal <HANDLE> \
  --text 'echo <base64-of-file> | base64 -d > /root/incoming.pub'
```

Hard rules, learned the hard way:

- **Only ever touch terminals this tool created.** Orca's terminal listing is worktree-wide and carries previews of every tab, including the agent's own. `scripts/orca_tty.py` records the handles it creates (`~/.orca-tty/created.json`), `list` hides every other terminal and returns no output for them, and any read or write through an unknown handle is refused — including the terminal the agent is running in. Never widen that: do not call `orca terminal read` / `orca terminal send` directly, and do not read the agent's own terminal "just to check something".
- **Resolve the CLI once per session.** `ORCA_CLI_COMMAND` → `orca-dev` (dev checkout) → `orca-ide` (Linux, outside an Orca terminal — bare `orca` there is the GNOME screen reader) → `orca`.
- **Never use `terminal wait --for tui-idle`.** Commands routinely finish before the wait starts, and the wait then hangs. Read with a cursor instead.
- **Read before you write.** `terminal read --cursor <n>` returns only new lines; keep the cursor.
- **Send multi-line anything as base64.** `echo <b64> | base64 -d | bash`. Heredocs and nested quotes through `terminal send` break in ways that are hard to see.
- **Poll for the shell prompt after `ssh`.** The user types the passphrase by hand; the assistant cannot supply it. Poll for `:~#`, then continue in the same turn.
- **`terminal_handle_stale` means the Orca app restarted** and took the session with it. Re-list terminals, create a new one, ask the user to authenticate again. Do not assume the old session still runs commands.
- **Ask the user not to toggle TUN / system proxy while you work.** An interactive SSH session routed over a TUN interface dies the moment TUN is switched off, mid-command, and the change you were applying may not have landed.
- **Never print the private key.** Generate secrets inside the remote script, keep them in shell variables, echo only public values (public key, uuid, short_id).

## 2. Preconditions, and Stage 0 when they are not met

- SSH access must work with a **passphrase-protected key**, and the passphrase stays with the user (a password manager). Never write it to disk, never echo it.
- If the host is still on password auth, or the user wants SSH moved to a high port, harden it now with `scripts/ssh_harden.sh`, **inside the session opened in §1**. It is staged so that no step can lock you out:

```bash
# [SERVER] inside the Orca terminal session, as root
[ "${ORCA:-}" = yes ] || { echo "refusing: ORCA != yes — run this inside the Orca session" >&2; false; } && {
# land the script first (§1), then drive its subcommands
bash /root/ssh_harden.sh status
bash /root/ssh_harden.sh preflight
echo <base64-of-pubkey> | base64 -d > /root/incoming.pub
bash /root/ssh_harden.sh install-key /root/incoming.pub   # or: install-key - < /root/incoming.pub
#   -> prove a key-only login from OUTSIDE on the current port
bash /root/ssh_harden.sh stage-port <user-chosen-port>
#   -> prove a login from OUTSIDE on the NEW port: this is the gate
bash /root/ssh_harden.sh converge-port <user-chosen-port>
bash /root/ssh_harden.sh disable-password
}
```

The public key starts on the client while the script runs on the server, so it has to be staged first; `install-key -` also reads it from stdin. When the port moves, the session you are holding stays alive on the old port — expected, and actually useful as a fallback.

Two traps it encodes, both of which make a naive fix silently do nothing:

- **A drop-in cannot override the main file above `Include`.** OpenSSH keeps the FIRST obtained value and `Include` sits partway down `sshd_config`, while vendor images often set live directives above it. `ssh_harden.sh status` prints which source wins for every keyword, and the setters edit that source rather than adding another file that loses.
- **Recent Ubuntu is socket-activated** (`ssh.socket`, `Accept=no`): a `Port` line in `sshd_config` is inert because `ListenStream` on the socket unit owns the port. Change the unit, `daemon-reload`, then restart **both** `ssh.socket` and `ssh.service` so sshd inherits the new fds.

Never converge the port before a fresh login on the new port has succeeded from outside. An existing session is not proof, and neither is a listening socket.

**Stop at the port step and ask the user which port to use.** It is their decision: the value ends up in their client config, their provider's firewall rules and their notes. Do not invent one and do not "just pick a random high port". Say what makes a good choice (anything from 1024 up; avoid the host's ephemeral range, which is `cat /proc/sys/net/ipv4/ip_local_port_range`; avoid the well-known alternate ports that scanners try first), then wait for an answer before running `stage-port`.

`stage-port` and `converge-port` both refuse a port that is already bound — checked twice, with `ss` and an actual bind attempt — and `converge-port` snapshots the old configuration, verifies the new port really listens, and rolls back if it does not. Converging is the one step that removes the old port, so a failed bind there would otherwise leave no listener at all.

## 3. Recon (read-only)

```bash
# [SERVER] inside the Orca terminal — nothing in this block is about your machine
[ "${ORCA:-}" = yes ] || { echo "refusing: ORCA != yes — run this inside the Orca session" >&2; false; } && {
. /etc/os-release; echo "$PRETTY_NAME $(uname -m)"; nproc; free -m | head -2; df -h / | tail -1
command -v sing-box && sing-box version || echo NO_SING_BOX
systemctl list-units --type=service --all --no-pager | grep -iE 'sing|xray|v2ray|reality'
ss -lntup
ufw status verbose
curl -sS -o /dev/null -w 'github=%{http_code}\n' --max-time 15 https://api.github.com/
}
```

Leave any pre-existing proxy daemon strictly alone: different unit name, different port.

## 4. Port and cover site

**Do not start this section before §1 and §2 have passed their gates.** Screening is cheap, which is exactly why it gets started while a login is still pending and turns into a false sense of progress.

**Port: 443.** Reality's whole value is that the IP genuinely serves a real TLS site there. A high port turns the camouflage into "some site on an odd port". Only move if 443 is occupied — and the port is the user's decision anyway (rule 13).

**Candidates: you generate them.** The user gives constraints in §0 — region, anything to avoid, or "you pick" — and is not expected to hand over a list. A list they volunteer is a better seed; one they never offered is not a prerequisite.

What qualifies as a cover site:

- a real, stable, **low-profile company** site: a few-person business, not a university, government body, transit authority, school district, news outlet, or anything whose outage makes the news;
- **never** `.gov`, `.edu`, `.mil` or a public institution — high profile, usually CDN-fronted, and a poor thing to hide traffic behind;
- TLS 1.3, X25519, ALPN `h2`, chain valid for that name; **not Cloudflare**, ideally no CDN/WAF at all (a plain origin — shared hosting, small VPS, regional ISP — is the best camouflage);
- in the same region as the node;
- **reachable from the node**, which is the only place that fact can be measured.

**Screen on the node, in one pass.** A single probe there answers both open questions — usable as a cover, and reachable from this node — and the second one cannot be answered anywhere else. Local screening answers only the first, and it answers it about your own network, so it decides nothing:

```bash
# [SERVER] screen and prove reachability at the same time — this is the decision
[ "${ORCA:-}" = yes ] && bash /root/sni_check_on_host.sh --file /root/candidates.txt
```

A local pre-filter is optional, only for long lists, and only after §1's gate has passed — it triages, it never decides:

```bash
# [LOCAL] optional triage; its verdict means nothing about the node
python scripts/sni_screen.py --file candidates.txt
```

If you do use the local pre-filter, `scripts/sni_screen.py` encodes two traps that silently produce garbage results:

- **A local Clash/proxy in fake-ip mode poisons plain DNS.** Every lookup returns the fake range (e.g. `198.18.0.0/15`), so an "is it Cloudflare" check passes everything. The script resolves over DoH and connects to the resolved IP with an explicit SNI, bypassing the local resolver.
- **Cloudflare's published range list is not exhaustive.** Some Cloudflare-fronted space sits outside it, and some platform ranges are announced by unrelated ASNs. The script cross-checks the ASN holder and flags CDN/WAF owners explicitly.

Also expect: a mismatched SNI returns the upstream host's default vhost certificate (normal on shared hosting), and a site that merely speaks TLS 1.3 but not h2 is unusable.

## 5. Install sing-box

```bash
# [SERVER] inside the Orca terminal
[ "${ORCA:-}" = yes ] || { echo "refusing: ORCA != yes — run this inside the Orca session" >&2; false; } && {
REL=$(curl -sS --max-time 25 https://api.github.com/repos/SagerNet/sing-box/releases/latest)
VER=$(echo "$REL" | grep -oP '"tag_name":\s*"\K[^"]+' | head -1)
curl -fsSL -o /tmp/sb.tgz "https://github.com/SagerNet/sing-box/releases/download/$VER/sing-box-${VER#v}-linux-amd64.tar.gz"
sha256sum /tmp/sb.tgz
tar xzf /tmp/sb.tgz -C /tmp && install -m0755 /tmp/sing-box-*/sing-box /usr/local/bin/sing-box
sing-box version
}
```

Report the version and the tarball hash so the artifact is auditable.

## 6. Secrets, config, unit

Use `scripts/node_setup.sh`. It is idempotent and SNI-swappable: on an existing config it **reuses** the private key, uuid and short_id and only changes `server_name` / `handshake.server`, which is exactly what a target swap needs.

```bash
# [SERVER] inside the Orca terminal — node_setup.sh lives there after §1
[ "${ORCA:-}" = yes ] && SNI=<domain> PORT=443 bash /root/node_setup.sh
```

What it enforces:

- `sing-box check` before every restart; abort on failure.
- A dedicated system account, config `0600`, so the private key is not world-readable.
- `AmbientCapabilities=CAP_NET_BIND_SERVICE` to bind :443 without root.
- `RestrictAddressFamilies` includes `AF_NETLINK` — sing-box aborts at startup without it.
- A backup of the previous config on every change.

The 1.14.x config shape (field names have moved across releases — always let `sing-box check` arbitrate). **File on the server:** `/etc/<name>/config.json`, written by `node_setup.sh`; shown here for review.

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
# [LOCAL] both probes run from your machine, outside the node
python scripts/node_verify.py --host <SERVER_IP> --port 443 --sni <SNI> --repeat 3
python scripts/client_e2e.py --sing-box <path-to-sing-box> \
    --server <SERVER_IP> --port 443 --uuid <UUID> --sni <SNI> --pbk <PUBLIC_KEY> --sid <SHORT_ID>
# [SERVER] restart proof — then repeat the [LOCAL] camouflage probe above
[ "${ORCA:-}" = yes ] && systemctl restart <unit>
```

1. **Camouflage / relay** — a plain TLS client presenting the configured SNI must receive the **real certificate of that site**, because unauthenticated handshakes are relayed to the target. This is also the cheapest health check.
2. **Real end-to-end** — a genuine client must egress as the node's IP via both HTTP and SOCKS5, and differently from a direct control.
3. **Restart survival** — a node that only works until the first restart is not done.

`scripts/node_verify.py` distinguishes "server sent zero bytes" (Reality could not reach its target) from "certificate mismatch" (wrong SNI or wrong target), which is the difference between a server fault and a client fault.

## 8. Client profile

Copy the user's own template and change **only** the node block: `server`, `port`, `uuid`, `servername`, `reality-opts`. Keep their DNS, TUN, groups and rules byte-identical — they chose those. **File on the client:** this entry inside their profile — it is a credential, keep it outside any repository.

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
# [SERVER] inside the Orca terminal — these read the node's own logs and its view of the target
[ "${ORCA:-}" = yes ] || { echo "refusing: ORCA != yes — run this inside the Orca session" >&2; false; } && {
journalctl -u <unit> -n 40 --no-pager | grep -i 'failed to dial dest'
curl -sS -o /dev/null -w '%{http_code} %{time_total}\n' --max-time 12 https://<SNI>/
}
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
