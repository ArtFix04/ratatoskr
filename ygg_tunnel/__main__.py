"""
ygg_tunnel CLI entry point.

Commands
--------
  run       Start the node (client / relay / exit — combinable)
  demo      Spin up a self-contained 3-hop demo circuit (no Yggdrasil needed)
  info      Show local Yggdrasil address and loaded identity
  peers     List, add, remove, or probe peers
  keygen    (Re-)generate identity keys

Examples
--------
  # Client + relay, CLI only (default):
  python -m ygg_tunnel run --no-require-ygg

  # Same but open the web UI in a browser:
  python -m ygg_tunnel run --no-require-ygg --ui

  # Exit node (explicit opt-in, web ports only):
  python -m ygg_tunnel run --exit --exit-policy "80,443" --no-client

  # Self-contained demo (no Yggdrasil, opens browser):
  python -m ygg_tunnel demo --ui
"""

from __future__ import annotations

import asyncio
import json
import logging
import pathlib
import sys
import webbrowser
from typing import Optional

import click

from .exit_policy import ExitPolicy
from .gateway import GatewayNode
from .keys import DEFAULT_CONFIG_DIR, NodeIdentity, load_or_create
from .peers import PeerInfo, PeerRegistry, _http_get, PEERS_HTTP_PORT
from .relay_log import RelayLog
from .yggdrasil import get_local_ygg_address

PEERS_FILE = DEFAULT_CONFIG_DIR / "peers.json"

# ---------------------------------------------------------------------------
# Known public bootstrap nodes
# These are long-running relay nodes operated for the demo / public use.
# Update this list when you deploy your own relay nodes.
# ---------------------------------------------------------------------------
BOOTSTRAP_PEERS: list[str] = [
    # Add Yggdrasil addresses of relay nodes here, e.g.:
    # "200:1234:5678:abcd::1",
]


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------

@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging.")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """Ygg-Tunnel — anonymized mesh proxy over Yggdrasil."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    _setup_logging(verbose)


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--socks-host", default="127.0.0.1", show_default=True,
              help="SOCKS5 listen address.")
@click.option("--socks-port", default=9050, show_default=True, type=int,
              help="SOCKS5 listen port.")
@click.option("--ygg-port", default=9051, show_default=True, type=int,
              help="Yggdrasil peer listener port.")
@click.option("--exit", "exit_mode", is_flag=True, default=False,
              help="Enable exit mode (opt-in). Your IP will be the egress point.")
@click.option("--exit-policy", "exit_policy_str", default=None, metavar="PORTS",
              help='Exit port allowlist: "80,443" or "*" for all. Default: 80,443,8080,8443.')
@click.option("--hops", default=3, show_default=True, type=int,
              help="Number of onion-routing hops (min 2). Higher = more anonymous, slower.")
@click.option("--no-client", is_flag=True, default=False,
              help="Disable the local SOCKS5 proxy (relay/exit-only node).")
@click.option("--no-relay", is_flag=True, default=False,
              help="Disable the Yggdrasil relay listener (client-only node).")
@click.option("--no-require-ygg", is_flag=True, default=False,
              help="Start even if no Yggdrasil interface is detected.")
@click.option("--bootstrap", "bootstrap_peers", multiple=True, metavar="ADDR",
              help="Yggdrasil address to bootstrap peer discovery from (repeatable).")
@click.option("--no-auto-bootstrap", is_flag=True, default=False,
              help="Disable automatic bootstrap from built-in public nodes.")
@click.option("--config-dir", default=str(DEFAULT_CONFIG_DIR), show_default=True,
              type=click.Path(), help="Directory for identity keys and peers.json.")
@click.option("--ui", "enable_ui", is_flag=True, default=False,
              help="Launch the web UI and open it in a browser.")
@click.option("--tray", "enable_tray", is_flag=True, default=False,
              help="Show a system tray icon (requires pystray + pillow).")
@click.option("--ui-port", default=8080, show_default=True, type=int,
              help="Port for the web UI (only used with --ui).")
@click.option("--ui-host", default="127.0.0.1", show_default=True,
              help="Host for the web UI (only used with --ui).")
@click.option("--ygg-addr", "ygg_addr_override", default=None,
              help="Override the detected Yggdrasil address (useful for testing).")
@click.pass_context
def run(
    ctx: click.Context,
    socks_host: str,
    socks_port: int,
    ygg_port: int,
    exit_mode: bool,
    exit_policy_str: Optional[str],
    hops: int,
    no_client: bool,
    no_relay: bool,
    no_require_ygg: bool,
    bootstrap_peers: tuple,
    no_auto_bootstrap: bool,
    config_dir: str,
    enable_ui: bool,
    enable_tray: bool,
    ui_port: int,
    ui_host: str,
    ygg_addr_override: Optional[str],
) -> None:
    """
    Start the node.

    \b
    By default starts as:  client (SOCKS5 on 127.0.0.1:9050) + relay
    Use --exit to additionally handle exit traffic (explicit opt-in).
    Use --no-client / --no-relay to change the combination.
    Use --ui to open the web dashboard in your browser.
    Use --tray to keep the app in the system tray.

    \b
    Configure your browser:
      SOCKS5 proxy → 127.0.0.1:9050
    """
    if exit_mode:
        click.echo(
            "WARNING: exit mode enabled — outbound traffic will appear to "
            "originate from this machine's IP address.",
            err=True,
        )

    cfg_dir = pathlib.Path(config_dir)
    identity = load_or_create(cfg_dir)

    registry = PeerRegistry()
    peers_file = cfg_dir / "peers.json"
    registry.load(peers_file)

    # Merge explicit + auto bootstrap sources
    all_bootstrap = list(bootstrap_peers)
    if not no_auto_bootstrap and BOOTSTRAP_PEERS:
        for addr in BOOTSTRAP_PEERS:
            if addr not in all_bootstrap:
                all_bootstrap.append(addr)

    # Exit policy
    exit_policy: Optional[ExitPolicy] = None
    if exit_mode:
        exit_policy = ExitPolicy.from_string(exit_policy_str) if exit_policy_str else ExitPolicy.default()
        click.echo(f"Exit policy     : {exit_policy.describe()}", err=True)

    # Relay log
    relay_log = RelayLog()

    # -- Build AppState --
    from .ui.state import AppState, attach_ui_log_handler
    state = AppState()
    attach_ui_log_handler(state)

    node = GatewayNode(
        identity=identity,
        registry=registry,
        socks_host=socks_host,
        socks_port=socks_port,
        ygg_port=ygg_port,
        exit_mode=exit_mode,
        client_mode=not no_client,
        relay_mode=not no_relay,
        require_ygg=not no_require_ygg,
        bootstrap_peers=all_bootstrap,
        state=state,
        ygg_addr_override=ygg_addr_override,
        exit_policy=exit_policy,
        relay_log=relay_log,
        circuit_hops=hops,
    )

    # System tray
    tray = None
    if enable_tray:
        from .tray import TrayIcon
        ui_url = f"http://{ui_host}:{ui_port}"
        tray = TrayIcon(ui_url=ui_url, node=node)
        tray.start()

    try:
        asyncio.run(
            _run_node(
                node=node,
                state=state,
                registry=registry,
                peers_file=peers_file,
                enable_ui=enable_ui,
                ui_host=ui_host,
                ui_port=ui_port,
                relay_log=relay_log,
            )
        )
    except RuntimeError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
    except KeyboardInterrupt:
        click.echo("\nShutting down.")
        registry.save(peers_file)
    finally:
        if tray:
            tray.stop()


async def _run_node(
    node: GatewayNode,
    state,
    registry: PeerRegistry,
    peers_file: pathlib.Path,
    enable_ui: bool,
    ui_host: str,
    ui_port: int,
    relay_log=None,
) -> None:
    extra_coros = []

    if enable_ui:
        import uvicorn
        from .ui.app import create_app

        app = create_app(state=state, registry=registry, node=node, relay_log=relay_log)
        uvi_config = uvicorn.Config(
            app,
            host=ui_host,
            port=ui_port,
            log_level="warning",
        )
        uvi_server = uvicorn.Server(uvi_config)
        extra_coros.append(uvi_server.serve())

        async def _open_browser():
            await asyncio.sleep(1.2)
            url = f"http://{ui_host}:{ui_port}"
            click.echo(f"Web UI: {url}")
            webbrowser.open(url)

        extra_coros.append(_open_browser())

    await node.serve_forever(extra_coros=extra_coros)


# ---------------------------------------------------------------------------
# demo
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--ui", "enable_ui", is_flag=True, default=False,
              help="Open the web dashboard while the demo runs.")
@click.option("--ui-port", default=8080, show_default=True, type=int)
@click.option("--ui-host", default="127.0.0.1", show_default=True)
@click.option("--socks-port", default=19050, show_default=True, type=int,
              help="Local SOCKS5 port for the demo client.")
@click.pass_context
def demo(
    ctx: click.Context,
    enable_ui: bool,
    ui_port: int,
    ui_host: str,
    socks_port: int,
) -> None:
    """
    Run a self-contained 3-hop demo circuit — no Yggdrasil required.

    \b
    Spins up guard (19001) + middle (19002) + exit (19003) relay nodes
    plus a client SOCKS5 proxy on 127.0.0.1:19050, all in-process.
    Perfect for showing the project working on a single machine.

    \b
    Configure your browser:
      SOCKS5 proxy → 127.0.0.1:19050
    """
    click.echo("Starting Ygg-Tunnel DEMO — 3-hop onion circuit on localhost")
    click.echo("=" * 60)
    click.echo("  Guard  relay : 127.0.0.1:19001")
    click.echo("  Middle relay : 127.0.0.1:19002")
    click.echo("  Exit   node  : 127.0.0.1:19003")
    click.echo(f"  Client SOCKS5: 127.0.0.1:{socks_port}")
    click.echo()
    click.echo("Point your browser's SOCKS5 proxy to "
               f"127.0.0.1:{socks_port}  (no auth)")
    click.echo()

    try:
        asyncio.run(
            _run_demo(
                enable_ui=enable_ui,
                ui_host=ui_host,
                ui_port=ui_port,
                socks_port=socks_port,
            )
        )
    except KeyboardInterrupt:
        click.echo("\nDemo stopped.")


async def _run_demo(
    enable_ui: bool,
    ui_host: str,
    ui_port: int,
    socks_port: int,
) -> None:
    """Spin up all demo nodes inside a single asyncio event loop."""
    GUARD_PORT  = 19001
    MIDDLE_PORT = 19002
    EXIT_PORT   = 19003

    guard_id  = NodeIdentity.generate()
    middle_id = NodeIdentity.generate()
    exit_id   = NodeIdentity.generate()
    client_id = NodeIdentity.generate()

    guard_peer  = PeerInfo("127.0.0.1", guard_id.public_key_b64,  guard_id.verify_key_b64,  ["relay"], port=GUARD_PORT)
    middle_peer = PeerInfo("127.0.0.1", middle_id.public_key_b64, middle_id.verify_key_b64, ["relay"], port=MIDDLE_PORT)
    exit_peer   = PeerInfo("127.0.0.1", exit_id.public_key_b64,   exit_id.verify_key_b64,   ["exit"],  port=EXIT_PORT)

    relay_log = RelayLog()

    def _make(identity, port, *, exit_mode=False, registry=None, client_socks=None):
        return GatewayNode(
            identity=identity,
            registry=registry or PeerRegistry(),
            socks_host="127.0.0.1",
            socks_port=client_socks or 19999,
            ygg_port=port,
            exit_mode=exit_mode,
            client_mode=client_socks is not None,
            relay_mode=True,
            require_ygg=False,
            ygg_addr_override="127.0.0.1",
            peers_http_port=None,
            exit_policy=ExitPolicy.allow_all_ports() if exit_mode else None,
            relay_log=relay_log,
        )

    guard_node  = _make(guard_id,  GUARD_PORT)
    middle_node = _make(middle_id, MIDDLE_PORT)
    exit_node   = _make(exit_id,   EXIT_PORT, exit_mode=True)

    client_registry = PeerRegistry()
    for p in [guard_peer, middle_peer, exit_peer]:
        client_registry.add(p)

    from .ui.state import AppState, attach_ui_log_handler
    state = AppState()
    state.demo_mode = True
    attach_ui_log_handler(state)

    client_node = _make(
        client_id,
        port=19999,
        registry=client_registry,
        client_socks=socks_port,
    )
    # Attach state to client node so UI reflects live stats
    client_node.state = state

    for node in [guard_node, middle_node, exit_node, client_node]:
        await node.start()

    servers = []
    for node in [guard_node, middle_node, exit_node, client_node]:
        servers.extend(node._servers)

    extra_coros = [srv.serve_forever() for srv in servers]

    if enable_ui:
        import uvicorn
        from .ui.app import create_app

        app = create_app(state=state, registry=client_registry, node=client_node, relay_log=relay_log)
        uvi_config = uvicorn.Config(app, host=ui_host, port=ui_port, log_level="warning")
        uvi_server = uvicorn.Server(uvi_config)
        extra_coros.append(uvi_server.serve())

        async def _open_browser():
            await asyncio.sleep(1.2)
            url = f"http://{ui_host}:{ui_port}"
            click.echo(f"Web UI: {url}")
            webbrowser.open(url)

        extra_coros.append(_open_browser())

    if extra_coros:
        await asyncio.gather(*extra_coros)


# ---------------------------------------------------------------------------
# test
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--config-dir", default=str(DEFAULT_CONFIG_DIR), show_default=True,
              type=click.Path())
@click.option("--hops", default=3, show_default=True, type=int,
              help="Circuit hops for the test.")
@click.option("--timeout", default=15.0, show_default=True, type=float,
              help="Seconds to wait for each step.")
def test(config_dir: str, hops: int, timeout: float) -> None:
    """
    Build a circuit and verify end-to-end connectivity.

    \b
    Connects to the Yggdrasil network, builds an onion circuit, fetches
    http://ifconfig.me/ip through it, and prints the exit node's IP.
    Requires peers in peers.json (run `python -m ygg_tunnel peers fetch` first).
    """
    cfg_dir = pathlib.Path(config_dir)
    load_or_create(cfg_dir)   # ensure identity exists

    registry = PeerRegistry()
    registry.load(cfg_dir / "peers.json")

    click.echo(f"Known peers : {len(registry)}  "
               f"(relay={len(registry.relays())} exit={len(registry.exits())})")

    if not registry.exits():
        click.echo("ERROR: No exit peers known. Add peers first with "
                   "`python -m ygg_tunnel peers fetch <addr> --save`", err=True)
        sys.exit(1)
    if len(registry.relays()) < hops - 1:
        click.echo(
            f"ERROR: Need ≥{hops - 1} relay peer(s) for a {hops}-hop circuit "
            f"(have {len(registry.relays())}).", err=True,
        )
        sys.exit(1)

    click.echo(f"Building {hops}-hop circuit …")
    try:
        asyncio.run(_run_test(registry, hops, timeout))
    except KeyboardInterrupt:
        click.echo("\nAborted.")
        sys.exit(1)


async def _run_test(registry: PeerRegistry, hops: int, timeout: float) -> None:
    from .circuit import CircuitManager

    manager = CircuitManager(registry, hops=hops)
    try:
        circuit = await asyncio.wait_for(manager.get_circuit(), timeout=timeout)
    except (RuntimeError, asyncio.TimeoutError) as exc:
        click.echo(f"Circuit build failed: {exc}", err=True)
        sys.exit(1)

    click.echo(f"Circuit : {circuit.describe()}")
    click.echo("Fetching http://ifconfig.me/ip …")

    try:
        reader, writer = await asyncio.wait_for(
            manager.open_stream("ifconfig.me", 80), timeout=timeout
        )
    except (OSError, RuntimeError, asyncio.TimeoutError) as exc:
        click.echo(f"Failed to open stream: {exc}", err=True)
        sys.exit(1)

    request = (
        "GET /ip HTTP/1.1\r\n"
        "Host: ifconfig.me\r\n"
        "User-Agent: ratatoskr/test\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    writer.write(request.encode())
    await writer.drain()

    try:
        response = b""
        while True:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            if not chunk:
                break
            response += chunk
    except asyncio.TimeoutError:
        click.echo("Timeout waiting for response.", err=True)
        writer.close()
        sys.exit(1)
    finally:
        if not writer.is_closing():
            writer.close()

    if b"\r\n\r\n" in response:
        body = response.split(b"\r\n\r\n", 1)[1].decode("utf-8", errors="replace").strip()
    else:
        body = response.decode("utf-8", errors="replace").strip()

    click.echo(f"Exit IP : {body}")
    click.echo("PASSED  — circuit is working.")


# ---------------------------------------------------------------------------
# info
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--config-dir", default=str(DEFAULT_CONFIG_DIR), show_default=True,
              type=click.Path())
def info(config_dir: str) -> None:
    """Show local Yggdrasil address and node identity."""
    cfg_dir = pathlib.Path(config_dir)
    ygg = get_local_ygg_address()

    click.echo(f"Yggdrasil addr  : {ygg or 'NOT DETECTED'}")
    if ygg:
        click.echo(f"Peer listener   : [{ygg}]:9051  (when running)")
        click.echo(f"Peers HTTP      : http://[{ygg}]:9052/peers  (when running)")
    click.echo(f"SOCKS5 proxy    : 127.0.0.1:9050  (when running)")
    click.echo(f"Web UI          : http://127.0.0.1:8080  (when running with --ui)")

    sign_path = cfg_dir / "identity.sign"
    if sign_path.exists():
        identity = load_or_create(cfg_dir)
        click.echo(f"Identity (sign) : {identity.verify_key_b64}")
        click.echo(f"Identity (enc)  : {identity.public_key_b64}")
    else:
        click.echo("Identity        : not yet generated (will be created on first `run`)")

    if BOOTSTRAP_PEERS:
        click.echo(f"Bootstrap nodes : {len(BOOTSTRAP_PEERS)} configured")
        for addr in BOOTSTRAP_PEERS:
            click.echo(f"  {addr}")
    else:
        click.echo("Bootstrap nodes : none configured (add to BOOTSTRAP_PEERS in __main__.py)")


# ---------------------------------------------------------------------------
# keygen
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--config-dir", default=str(DEFAULT_CONFIG_DIR), show_default=True,
              type=click.Path())
@click.option("--force", is_flag=True, default=False,
              help="Overwrite existing keys.")
def keygen(config_dir: str, force: bool) -> None:
    """Generate (or regenerate) identity keys."""
    cfg_dir = pathlib.Path(config_dir)
    sign_path = cfg_dir / "identity.sign"
    if sign_path.exists() and not force:
        click.echo("Keys already exist. Use --force to overwrite.", err=True)
        sys.exit(1)
    identity = NodeIdentity.generate()
    identity.save(cfg_dir)
    click.echo(f"New identity saved to {cfg_dir}")
    click.echo(f"  sign pubkey : {identity.verify_key_b64}")
    click.echo(f"  enc  pubkey : {identity.public_key_b64}")


# ---------------------------------------------------------------------------
# peers
# ---------------------------------------------------------------------------

@cli.group()
def peers() -> None:
    """Manage known Yggdrasil peers."""


@peers.command("list")
@click.option("--config-dir", default=str(DEFAULT_CONFIG_DIR), show_default=True,
              type=click.Path())
def peers_list(config_dir: str) -> None:
    """List all known peers."""
    registry = PeerRegistry()
    registry.load(pathlib.Path(config_dir) / "peers.json")
    if not registry.all():
        click.echo("No peers known yet.")
        return
    for p in registry.all():
        modes = ",".join(p.modes)
        click.echo(f"  [{p.addr}]:{p.port}  modes={modes}  enc={p.pubkey_enc[:16]}...")


@peers.command("add")
@click.argument("addr")
@click.argument("pubkey_enc")
@click.argument("pubkey_sign")
@click.option("--modes", default="relay", show_default=True,
              help="Comma-separated modes: relay,exit")
@click.option("--port", default=9051, show_default=True, type=int)
@click.option("--config-dir", default=str(DEFAULT_CONFIG_DIR), show_default=True,
              type=click.Path())
def peers_add(addr, pubkey_enc, pubkey_sign, modes, port, config_dir):
    """Manually add a peer by address and public keys."""
    cfg_dir = pathlib.Path(config_dir)
    registry = PeerRegistry()
    peers_file = cfg_dir / "peers.json"
    registry.load(peers_file)
    registry.add(PeerInfo(
        addr=addr,
        pubkey_enc=pubkey_enc,
        pubkey_sign=pubkey_sign,
        modes=modes.split(","),
        port=port,
    ))
    registry.save(peers_file)
    click.echo(f"Added peer {addr}")


@peers.command("remove")
@click.argument("addr")
@click.option("--config-dir", default=str(DEFAULT_CONFIG_DIR), show_default=True,
              type=click.Path())
def peers_remove(addr, config_dir):
    """Remove a peer by address."""
    cfg_dir = pathlib.Path(config_dir)
    registry = PeerRegistry()
    peers_file = cfg_dir / "peers.json"
    registry.load(peers_file)
    registry.remove(addr)
    registry.save(peers_file)
    click.echo(f"Removed {addr} (if it existed)")


@peers.command("fetch")
@click.argument("addr")
@click.option("--port", default=PEERS_HTTP_PORT, show_default=True, type=int)
@click.option("--save", is_flag=True, default=False,
              help="Merge fetched peers into local peers.json")
@click.option("--config-dir", default=str(DEFAULT_CONFIG_DIR), show_default=True,
              type=click.Path())
def peers_fetch(addr, port, save, config_dir):
    """Fetch the peer list from a running node."""
    async def _run():
        raw = await _http_get(addr, port, "/peers", timeout=5.0)
        if raw is None:
            click.echo(f"Could not reach {addr}:{port}", err=True)
            return
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            click.echo("Invalid JSON response", err=True)
            return

        fetched = [PeerInfo.from_dict(d) for d in data.get("peers", [])]
        click.echo(f"Received {len(fetched)} peers from {addr}:")
        for p in fetched:
            click.echo(f"  [{p.addr}]:{p.port}  modes={','.join(p.modes)}")

        if save:
            cfg_dir = pathlib.Path(config_dir)
            registry = PeerRegistry()
            peers_file = cfg_dir / "peers.json"
            registry.load(peers_file)
            new = registry.update_from_list(fetched)
            registry.save(peers_file)
            click.echo(f"Saved ({new} new entries).")

    asyncio.run(_run())


@peers.command("probe")
@click.argument("addr")
@click.option("--port", default=PEERS_HTTP_PORT, show_default=True, type=int)
def peers_probe(addr, port):
    """Check if a node is reachable and print its identity."""
    async def _run():
        raw = await _http_get(addr, port, "/peers", timeout=3.0)
        if raw is None:
            click.echo(f"UNREACHABLE  {addr}:{port}")
            return
        try:
            data = json.loads(raw)
            self_peers = [p for p in data.get("peers", []) if p.get("addr") == addr]
            if self_peers:
                p = self_peers[0]
                click.echo(f"ONLINE  {addr}:{port}")
                click.echo(f"  modes   : {','.join(p.get('modes', []))}")
                click.echo(f"  enc key : {p.get('pubkey_enc', '?')[:32]}...")
            else:
                click.echo(f"ONLINE  {addr}:{port}  (no self-entry in response)")
        except (json.JSONDecodeError, KeyError):
            click.echo(f"ONLINE  {addr}:{port}  (malformed response)")

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()
