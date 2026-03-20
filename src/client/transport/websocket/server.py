from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

import websockets
from websockets.exceptions import ConnectionClosed

from client.bootstrap.config import AppConfig
from client.integrations.eimzo_api import EimzoApiClient
from client.system.certificates import build_websocket_server_ssl_context
from client.transport.websocket.messages import parse_proxy_command

LOGGER = logging.getLogger(__name__)


class WebSocketProxyServer:
    def __init__(
        self,
        *,
        config: AppConfig,
        endpoint_proxy: EimzoApiClient,
        server_cert_path: Path,
        server_key_path: Path,
        certificate_rotation_event: asyncio.Event,
    ) -> None:
        self._config = config
        self._endpoint_proxy = endpoint_proxy
        self._server_cert_path = server_cert_path
        self._server_key_path = server_key_path
        self._certificate_rotation_event = certificate_rotation_event

    async def run_forever(self) -> None:
        while True:
            try:
                await self._serve_until_certificate_rotation()
            except asyncio.CancelledError:
                raise
            except Exception:
                LOGGER.exception(
                    "Local WSS server failed. Restarting in %.1f seconds.",
                    self._config.server_retry_delay_seconds,
                )
                await asyncio.sleep(self._config.server_retry_delay_seconds)

    async def _serve_until_certificate_rotation(self) -> None:
        self._certificate_rotation_event.clear()
        ssl_context = build_websocket_server_ssl_context(
            cert_path=self._server_cert_path,
            key_path=self._server_key_path,
        )

        async with websockets.serve(
            self._handle_connection,
            host=self._config.ws_host,
            port=self._config.ws_port,
            ssl=ssl_context,
            ping_interval=self._config.ws_ping_interval_seconds,
            ping_timeout=self._config.ws_ping_timeout_seconds,
        ):
            LOGGER.info("Local WSS server is listening on %s", self._config.websocket_bind_url())
            await self._certificate_rotation_event.wait()
            LOGGER.info("Reloading local WSS server to apply renewed certificate.")

    async def _handle_connection(self, websocket: Any, path: str | None = None) -> None:
        request_path = self._resolve_request_path(websocket, path)
        if not self._config.matches_websocket_path(request_path):
            LOGGER.warning("Rejected WSS connection on unexpected path: %s", request_path)
            await websocket.close(code=1008, reason="Unexpected WebSocket path")
            return

        LOGGER.info("Accepted local WSS connection on path %s", request_path)

        try:
            async for raw_message in websocket:
                await self._handle_message(websocket, raw_message)
        except ConnectionClosed:
            LOGGER.info("Local WSS connection closed on path %s", request_path)

    async def _handle_message(self, websocket: Any, raw_message: str | bytes) -> None:
        try:
            command = parse_proxy_command(raw_message)
            response = await self._endpoint_proxy.forward(command)
            await websocket.send(response.to_websocket_payload())
        except Exception:
            LOGGER.exception("Failed to process local WSS message.")

    def _resolve_request_path(self, websocket: Any, path: str | None) -> str | None:
        if path is not None:
            return path

        websocket_path = getattr(websocket, "path", None)
        if websocket_path is not None:
            return websocket_path

        request = getattr(websocket, "request", None)
        if request is not None:
            return getattr(request, "path", None)

        return None
