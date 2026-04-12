# Ratatoskr

> *In Norse mythology, Ratatoskr is the squirrel that endlessly runs up and down Yggdrasil —
> the world tree — carrying messages between the eagle at the crown and the serpent at the roots.
> Neither knows the other. Neither knows the messenger's full path.*

Tor-style onion routing over the [Yggdrasil Network](https://yggdrasil-network.github.io/).
Traffic is routed through a 3-hop encrypted circuit before exiting to the public internet,
so no single node can see both who you are and what you're visiting.

```
You → [Guard] → [Middle] → [Exit] → Internet
        ↑           ↑         ↑
   knows you    knows      knows
   not dest.    neither    dest, not you
```

---

## Features

- **3-hop onion routing** — each hop peels one encryption layer (like Tor)
- **NaCl crypto** — X25519 key exchange + XSalsa20-Poly1305 per hop
- **SOCKS5 proxy** — point any app (browser, curl) at `127.0.0.1:9050`
- **Peer discovery** — nodes self-announce to bootstrap peers; liveness pruning removes dead nodes
- **Exit policy** — explicit opt-in with port allowlist (default: 80, 443, 8080, 8443)
- **Web UI** — live dashboard, relay log, peer manager, settings (`--ui`)
- **System tray** — menu-bar icon with connect/disconnect toggle (`--tray`)
- **Demo mode** — full 3-hop circuit on a single machine, no Yggdrasil required

---

## Requirements

- Python 3.11+
- [Yggdrasil](https://yggdrasil-network.github.io/installation.html) installed and running
  (not required for `demo` mode)

```bash
pip install -r requirements.txt
```

---

## Quick start

### Demo (single machine, no Yggdrasil needed)

```bash
python -m ygg_tunnel demo --ui
```

Spins up guard + middle + exit nodes all in-process, opens the dashboard, and prints:

```
Point your browser's SOCKS5 proxy to 127.0.0.1:19050  (no auth)
```

Test it:

```bash
curl --socks5 127.0.0.1:19050 https://ifconfig.me
```

### Real node (requires Yggdrasil)

```bash
# Client + relay (default)
python -m ygg_tunnel run --ui

# Exit node (opt-in — your IP will be the egress point)
python -m ygg_tunnel run --exit --exit-policy "80,443"

# Relay only (no local SOCKS5 proxy)
python -m ygg_tunnel run --no-client
```

Configure your browser's SOCKS5 proxy to `127.0.0.1:9050` (no auth).

---

## Commands

```
python -m ygg_tunnel [OPTIONS] COMMAND

Commands:
  run      Start the node (client / relay / exit)
  demo     Self-contained 3-hop demo, no Yggdrasil required
  info     Show Yggdrasil address and node identity
  keygen   Generate or regenerate identity keys
  peers    Manage known peers (list / add / remove / fetch / probe)
```

### `run` flags

| Flag | Default | Description |
|------|---------|-------------|
| `--socks-port` | 9050 | SOCKS5 listen port |
| `--exit` | off | Enable exit node (opt-in) |
| `--exit-policy` | `80,443,8080,8443` | Port allowlist for exit node |
| `--no-client` | off | Disable SOCKS5 (relay/exit only) |
| `--no-relay` | off | Disable relay listener |
| `--bootstrap ADDR` | — | Extra bootstrap node address (repeatable) |
| `--ui` | off | Open web dashboard in browser |
| `--ui-port` | 8080 | Web UI port |
| `--tray` | off | System tray icon |
| `--no-require-ygg` | off | Start without a detected Yggdrasil interface |

### `peers` subcommands

```bash
python -m ygg_tunnel peers list
python -m ygg_tunnel peers fetch <ygg-addr> [--save]
python -m ygg_tunnel peers probe <ygg-addr>
python -m ygg_tunnel peers add  <addr> <pubkey_enc> <pubkey_sign>
python -m ygg_tunnel peers remove <addr>
```

---

## Web UI

Start with `--ui` to open the dashboard at `http://127.0.0.1:8080`.

| Page | Description |
|------|-------------|
| Dashboard | Connection status, live throughput chart, relay stats |
| Peers | Known peers, add/remove/fetch from remote node |
| Relay Log | Per-event proof-of-relay table (bytes, hops, targets) |
| Settings | Node mode, exit policy, SOCKS5 status, identity keys |
| Logs | Live log viewer with level filter |

---

## Architecture

### Anonymity model

The same threat model as Tor:

- **Guard** knows your IP and the middle node's address — not the destination
- **Middle** knows guard and exit — not you or the destination
- **Exit** knows the middle and the destination — not you
- **You** (the client) know the full circuit — this is normal; the dashboard shows it, just as Tor Browser does

No single node can link source to destination. Correlation attacks (watching both ends simultaneously) are the same hard problem as in Tor.

### Packet wire format

```
| version(1) | msg_type(1) | hop_len(1) | next_hop(hop_len) | payload_len(4) | payload |
```

Message types: `ONION_RELAY (0x11)`, `ONION_EXIT (0x12)`, `ONION_RESP (0x13)`

### Crypto stack

- **Identity**: Ed25519 keypair — persisted to `~/.config/ratatoskr/`, used for peer list signing
- **Per-circuit key exchange**: X25519 ECDH ephemeral keys (forward secrecy)
- **Per-hop encryption**: NaCl SealedBox (XSalsa20-Poly1305)
- **Library**: [PyNaCl](https://pynacl.readthedocs.io/)

### Peer discovery

1. On startup, node fetches peer lists from bootstrap addresses and crawls transitively (2 hops)
2. Node POSTs its own `PeerInfo` to each bootstrap via `POST /peers/announce`
3. Bootstrap maintains a live registry; a background loop probes all peers every 60 s and removes nodes that fail 3 consecutive probes

---

## Deploying relay nodes

Any machine running Yggdrasil can be a relay. Yggdrasil addresses (`200::/7`) are derived from the node's public key — they never change regardless of IP address, NAT, or ISP.

```bash
# On the relay machine
pip install -r requirements.txt
python -m ygg_tunnel run --no-client        # relay only
python -m ygg_tunnel info                   # prints the 200:: address
```

Add the printed address to `BOOTSTRAP_PEERS` in `ygg_tunnel/__main__.py` so new nodes discover it automatically:

```python
BOOTSTRAP_PEERS: list[str] = [
    "200:xxxx:xxxx:xxxx::1",   # your relay's Yggdrasil address
]
```

Exit nodes need an additional flag:

```bash
python -m ygg_tunnel run --no-client --exit --exit-policy "80,443"
```

---

## Identity keys

Keys are auto-generated on first `run` and stored at `~/.config/ratatoskr/` (chmod 600).

```bash
python -m ygg_tunnel keygen          # generate (skips if already exists)
python -m ygg_tunnel keygen --force  # regenerate (changes your node identity)
python -m ygg_tunnel info            # print current keys and Yggdrasil address
```

---

## Project structure

```
ygg_tunnel/
  __main__.py     CLI entry point (click)
  gateway.py      GatewayNode — SOCKS5 + onion relay/exit handler
  circuit.py      Circuit, onion builder, CircuitManager
  crypto.py       encrypt_for / decrypt_layer (NaCl SealedBox)
  keys.py         NodeIdentity — Ed25519 + X25519, load/save
  packet.py       Wire format + stream reader
  peers.py        PeerInfo, PeerRegistry, GET/POST /peers HTTP server
  socks5.py       Async SOCKS5 server (RFC 1928, CONNECT)
  yggdrasil.py    Yggdrasil address detection (cross-platform)
  exit_policy.py  Port allowlist for exit nodes
  relay_log.py    Proof-of-relay JSONL log
  tray.py         System tray icon (pystray)
  ui/
    app.py        FastAPI app — all HTML + REST + WebSocket routes
    state.py      AppState — live stats, throughput history, log buffer
    templates/    Jinja2 HTML pages
    static/       CSS + JS
```
