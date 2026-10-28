"""Exercise the packaged client without login, persistent settings or OS integration."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from client import __version__


def run_self_test(report_path: Path) -> int:
    report: dict[str, Any] = {"version": __version__, "success": False, "checks": []}
    try:
        from client.main import _install_windows_event_loop, _load_run_app

        _load_run_app()
        report["checks"].append("application_import")
        _check_tkinter_window()
        report["checks"].append("tkinter_window")
        _install_windows_event_loop()
        asyncio.run(_check_websocket_transport())
        report["checks"].append("websocket_duplicate_origin")
        report["success"] = True
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if report["success"] else 1


def _check_tkinter_window() -> None:
    import tkinter as tk
    from tkinter import messagebox, simpledialog, ttk

    root = tk.Tk()
    root.withdraw()
    try:
        value = tk.StringVar(master=root, value="self-test")
        entry = ttk.Entry(root, textvariable=value)
        root.update_idletasks()
        if entry.get() != "self-test":
            raise RuntimeError("Tkinter widget initialization failed")
    finally:
        root.destroy()


async def _check_websocket_transport() -> None:
    from websockets.legacy.client import connect
    from websockets.legacy.server import serve

    from client.integrations.eimzo_api import ProxyResponse
    from client.transport.websocket.server import WebSocketProxyServer

    class Proxy:
        async def forward(self, command: Any, *, origin: str | None) -> ProxyResponse:
            return ProxyResponse.from_json({"success": True, "origin": origin, "id": command.request_id})

    server = WebSocketProxyServer(
        config=SimpleNamespace(matches_websocket_path=lambda path: path == "/"),
        endpoint_proxy=Proxy(),
        server_cert_path=Path("unused"),
        server_key_path=Path("unused"),
        certificate_rotation_event=asyncio.Event(),
    )
    async with serve(server._handle_connection, "127.0.0.1", 0,
                     process_request=server._process_opening_handshake_request) as listener:
        port = listener.sockets[0].getsockname()[1]
        async with connect(f"ws://127.0.0.1:{port}/", extra_headers=[
            ("Origin", "localhost"), ("origin", "localhost"),
        ], open_timeout=5) as websocket:
            await websocket.send('{"name":"version","id":"self-test"}')
            response = json.loads(await asyncio.wait_for(websocket.recv(), timeout=5))
            if response != {"success": True, "origin": "localhost", "id": "self-test"}:
                raise RuntimeError("Packaged WebSocket transport check failed")
