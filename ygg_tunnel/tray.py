"""
System-tray icon for Ygg-Tunnel.

Keeps the app alive after the browser tab is closed.  Menu items:
  • Open Dashboard  — re-opens the web UI in the default browser
  • ─────────────
  • Connected / Disconnected  (greyed-out status label)
  • Connect / Disconnect       (toggle SOCKS5 proxy)
  • ─────────────
  • Quit

The icon is drawn programmatically with Pillow so there are no asset files
to bundle.  A small "Y" glyph on a dark background, with a green dot when
connected and a grey dot when disconnected.

Usage
-----
    from ygg_tunnel.tray import TrayIcon
    tray = TrayIcon(ui_url="http://127.0.0.1:8080", node=gateway_node)
    tray.start()   # launches the pystray thread; returns immediately
    ...
    tray.stop()    # call on shutdown
"""

from __future__ import annotations

import logging
import threading
import webbrowser
from typing import TYPE_CHECKING, Callable, Optional

log = logging.getLogger(__name__)

if TYPE_CHECKING:
    from .gateway import GatewayNode


# ---------------------------------------------------------------------------
# Icon drawing (Pillow)
# ---------------------------------------------------------------------------

def _make_icon(connected: bool):
    """Return a PIL Image for the tray icon (64×64)."""
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        log.warning("Pillow not installed — tray icon will be blank")
        from PIL import Image
        return Image.new("RGBA", (64, 64), (40, 40, 40, 255))

    img = Image.new("RGBA", (64, 64), (30, 30, 30, 255))
    draw = ImageDraw.Draw(img)

    # "Y" glyph
    draw.line([(16, 8), (32, 32)], fill=(180, 140, 255), width=5)
    draw.line([(48, 8), (32, 32)], fill=(180, 140, 255), width=5)
    draw.line([(32, 32), (32, 56)], fill=(180, 140, 255), width=5)

    # Status dot (bottom-right)
    dot_color = (50, 200, 100) if connected else (120, 120, 120)
    draw.ellipse([(44, 44), (60, 60)], fill=dot_color)

    return img


# ---------------------------------------------------------------------------
# TrayIcon
# ---------------------------------------------------------------------------

class TrayIcon:
    """
    Wraps a pystray.Icon instance.  Runs in a dedicated daemon thread so it
    never blocks the asyncio event loop.
    """

    def __init__(
        self,
        ui_url: str = "http://127.0.0.1:8080",
        node: Optional["GatewayNode"] = None,
        quit_callback: Optional[Callable[[], None]] = None,
    ) -> None:
        self.ui_url = ui_url
        self.node = node
        self.quit_callback = quit_callback

        self._connected = True   # optimistic — mirrors SOCKS5 running state
        self._icon = None        # pystray.Icon, created in start()
        self._thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Spawn the tray icon in a background daemon thread."""
        try:
            import pystray
        except ImportError:
            log.warning("pystray not installed — system tray disabled")
            return

        self._icon = pystray.Icon(
            "ratatoskr",
            icon=_make_icon(self._connected),
            title="Ratatoskr",
            menu=self._build_menu(),
        )

        self._thread = threading.Thread(
            target=self._icon.run,
            name="tray-icon",
            daemon=True,
        )
        self._thread.start()
        log.info("System tray icon started")

    def stop(self) -> None:
        if self._icon is not None:
            try:
                self._icon.stop()
            except Exception:
                pass

    def set_connected(self, connected: bool) -> None:
        """Update the icon dot and menu label to reflect connection state."""
        self._connected = connected
        if self._icon is not None:
            self._icon.icon = _make_icon(connected)
            self._icon.menu = self._build_menu()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _build_menu(self):
        import pystray

        status_label = "● Connected" if self._connected else "○ Disconnected"

        def open_ui(icon, item):
            webbrowser.open(self.ui_url)

        def toggle_connection(icon, item):
            import asyncio
            if self.node is None:
                return
            loop = asyncio.new_event_loop()
            try:
                if self._connected:
                    loop.run_until_complete(self.node.pause_socks5())
                    self.set_connected(False)
                else:
                    loop.run_until_complete(self.node.resume_socks5())
                    self.set_connected(True)
            finally:
                loop.close()

        def quit_app(icon, item):
            icon.stop()
            if self.quit_callback:
                self.quit_callback()

        toggle_label = "Disconnect" if self._connected else "Connect"

        return pystray.Menu(
            pystray.MenuItem("Open Dashboard", open_ui, default=True),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(status_label, None, enabled=False),
            pystray.MenuItem(toggle_label, toggle_connection),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", quit_app),
        )
