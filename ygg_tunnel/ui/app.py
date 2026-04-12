"""
FastAPI web application for the Ygg-Tunnel UI.

Activated only when the user passes `--ui` to `python -m ygg_tunnel run`.
The CLI continues to work identically without it.

Routes
------
  GET  /                    → redirect to /dashboard
  GET  /dashboard           → dashboard page
  GET  /peers               → peers page
  GET  /settings            → settings page
  GET  /logs                → logs page

  WS   /ws/stats            → pushes JSON state every second

  GET  /api/status          → current AppState as JSON
  GET  /api/peers           → peer list as JSON
  POST /api/peers           → add a peer   { addr, pubkey_enc, pubkey_sign, modes, port }
  DELETE /api/peers/{addr}  → remove a peer
  POST /api/peers/fetch     → fetch from remote node { addr, port?, save? }
  POST /api/socks/pause     → stop accepting new SOCKS5 connections
  POST /api/socks/resume    → resume accepting SOCKS5 connections
"""

from __future__ import annotations

import asyncio
import json
import pathlib
from typing import Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from ..peers import PeerInfo, PeerRegistry, _http_get, PEERS_HTTP_PORT

HERE = pathlib.Path(__file__).parent


def _make_jinja_env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(HERE / "templates")),
        autoescape=select_autoescape(["html"]),
    )
    # filesizeformat filter (like Django's)
    def filesizeformat(value):
        try:
            n = int(value)
        except (TypeError, ValueError):
            return str(value)
        if n < 1024:
            return f"{n} B"
        if n < 1024 ** 2:
            return f"{n / 1024:.1f} KB"
        if n < 1024 ** 3:
            return f"{n / 1024 ** 2:.1f} MB"
        return f"{n / 1024 ** 3:.2f} GB"

    env.filters["filesizeformat"] = filesizeformat
    return env


def create_app(state, registry: PeerRegistry, node, relay_log=None) -> FastAPI:
    """
    Build and return the FastAPI application.

    Parameters
    ----------
    state    : AppState   — live node state (read by routes)
    registry : PeerRegistry — mutable peer list
    node     : GatewayNode  — for pause/resume SOCKS5
    """
    app = FastAPI(title="Ygg-Tunnel", docs_url=None, redoc_url=None)

    app.mount(
        "/static",
        StaticFiles(directory=str(HERE / "static")),
        name="static",
    )
    jinja = _make_jinja_env()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _render(template_name: str, **ctx) -> HTMLResponse:
        tpl = jinja.get_template(template_name)
        return HTMLResponse(tpl.render(state=state, **ctx))

    # ------------------------------------------------------------------
    # HTML pages
    # ------------------------------------------------------------------

    @app.get("/", response_class=RedirectResponse)
    async def root():
        return RedirectResponse("/dashboard")

    @app.get("/dashboard", response_class=HTMLResponse)
    async def dashboard():
        return _render("dashboard.html", page="dashboard")

    @app.get("/peers", response_class=HTMLResponse)
    async def peers_page():
        return _render("peers.html", page="peers", peers=registry.all())

    @app.get("/settings", response_class=HTMLResponse)
    async def settings_page():
        return _render("settings.html", page="settings")

    @app.get("/logs", response_class=HTMLResponse)
    async def logs_page():
        return _render("logs.html", page="logs", log_lines=list(state.log_lines))

    @app.get("/relay-log", response_class=HTMLResponse)
    async def relay_log_page():
        entries = relay_log.recent(100) if relay_log is not None else []
        stats   = relay_log.stats()    if relay_log is not None else {}
        return _render("relay_log.html", page="relay_log", entries=entries, stats=stats)

    # ------------------------------------------------------------------
    # WebSocket — live stats (push every second)
    # ------------------------------------------------------------------

    @app.websocket("/ws/stats")
    async def ws_stats(websocket: WebSocket):
        await websocket.accept()
        q = state.subscribe()
        # send current state immediately on connect
        await websocket.send_text(json.dumps(state.to_dict()))
        try:
            while True:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=1.5)
                    await websocket.send_text(msg)
                except asyncio.TimeoutError:
                    # keepalive ping
                    await websocket.send_text(json.dumps(state.to_dict()))
        except (WebSocketDisconnect, Exception):
            pass
        finally:
            state.unsubscribe(q)

    # ------------------------------------------------------------------
    # REST — status
    # ------------------------------------------------------------------

    @app.get("/api/status")
    async def api_status():
        return state.to_dict()

    @app.get("/api/logs")
    async def api_logs():
        return {"lines": list(state.log_lines)}

    # ------------------------------------------------------------------
    # REST — peers
    # ------------------------------------------------------------------

    @app.get("/api/peers")
    async def api_peers_list():
        return {"peers": [p.to_dict() for p in registry.all()]}

    @app.post("/api/peers")
    async def api_peers_add(
        addr: str = Form(...),
        pubkey_enc: str = Form(...),
        pubkey_sign: str = Form(...),
        modes: str = Form("relay"),
        port: int = Form(9051),
    ):
        peer = PeerInfo(
            addr=addr,
            pubkey_enc=pubkey_enc,
            pubkey_sign=pubkey_sign,
            modes=[m.strip() for m in modes.split(",")],
            port=port,
        )
        registry.add(peer)
        _autosave(registry)
        return {"ok": True, "addr": addr}

    @app.delete("/api/peers/{addr:path}")
    async def api_peers_remove(addr: str):
        registry.remove(addr)
        _autosave(registry)
        return {"ok": True}

    @app.post("/api/peers/fetch")
    async def api_peers_fetch(
        addr: str = Form(...),
        port: int = Form(PEERS_HTTP_PORT),
        save: bool = Form(False),
    ):
        raw = await _http_get(addr, port, "/peers", timeout=5.0)
        if raw is None:
            return JSONResponse({"error": f"Cannot reach {addr}:{port}"}, status_code=502)
        try:
            data = json.loads(raw)
            fetched = [PeerInfo.from_dict(d) for d in data.get("peers", [])]
        except (json.JSONDecodeError, KeyError) as exc:
            return JSONResponse({"error": str(exc)}, status_code=502)

        new_count = 0
        if save:
            new_count = registry.update_from_list(fetched)
            _autosave(registry)

        return {
            "ok": True,
            "fetched": [p.to_dict() for p in fetched],
            "new": new_count,
        }

    # ------------------------------------------------------------------
    # REST — SOCKS5 pause/resume
    # ------------------------------------------------------------------

    @app.post("/api/socks/pause")
    async def api_socks_pause():
        if node is not None:
            await node.pause_socks5()
        return {"ok": True, "socks_running": state.socks_running}

    @app.post("/api/socks/resume")
    async def api_socks_resume():
        if node is not None:
            await node.resume_socks5()
        return {"ok": True, "socks_running": state.socks_running}

    # ------------------------------------------------------------------
    # REST — relay log stats
    # ------------------------------------------------------------------

    @app.get("/api/relay-stats")
    async def api_relay_stats():
        if relay_log is not None:
            return relay_log.stats()
        return state.relay_stats or {}

    @app.get("/api/relay-log")
    async def api_relay_log(n: int = 50):
        if relay_log is not None:
            return {"entries": relay_log.recent(n)}
        return {"entries": []}

    # ------------------------------------------------------------------
    # Background broadcast task
    # ------------------------------------------------------------------

    @app.on_event("startup")
    async def _start_broadcaster():
        asyncio.ensure_future(_broadcast_loop(state, relay_log))

    return app


async def _broadcast_loop(state, relay_log=None) -> None:
    """Broadcast state to all WS subscribers once per second."""
    while True:
        await asyncio.sleep(1)
        state.sample_throughput()
        if relay_log is not None:
            state.relay_stats = relay_log.stats()
        await state.broadcast()


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _autosave(registry: PeerRegistry) -> None:
    from ..keys import DEFAULT_CONFIG_DIR
    try:
        registry.save(DEFAULT_CONFIG_DIR / "peers.json")
    except Exception:
        pass
