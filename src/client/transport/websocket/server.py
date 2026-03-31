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
_USER_ACTION_LOG_EXTRA = {"user_action": True}


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
        origin = self._resolve_request_origin(websocket)
        remote_address = self._resolve_remote_address(websocket)
        if not self._config.matches_websocket_path(request_path):
            LOGGER.warning(
                "Rejected WSS connection on unexpected path: path=%s origin=%s remote=%s",
                request_path,
                origin,
                remote_address,
                extra=_USER_ACTION_LOG_EXTRA,
            )
            await websocket.close(code=1008, reason="Unexpected WebSocket path")
            return

        try:
            async for raw_message in websocket:
                await self._handle_message(
                    websocket,
                    raw_message,
                    request_path=request_path,
                    origin=origin,
                    remote_address=remote_address,
                )
        except ConnectionClosed:
            LOGGER.info(
                "Local WSS connection closed: path=%s origin=%s remote=%s",
                request_path,
                origin,
                remote_address,
            )

    async def _handle_message(
        self,
        websocket: Any,
        raw_message: str | bytes,
        *,
        request_path: str | None,
        origin: str | None,
        remote_address: str | None,
    ) -> None:
        try:
            command = parse_proxy_command(raw_message)
            command_label = _format_command_label(command.plugin, command.name)
            LOGGER.info(
                "Received WSS command: command=%s has_arguments=%s origin=%s path=%s remote=%s",
                command_label,
                command.has_arguments,
                origin,
                request_path,
                remote_address,
                extra=_USER_ACTION_LOG_EXTRA,
            )
            response = await self._endpoint_proxy.forward(command)
            await websocket.send(response.to_websocket_payload())
        except Exception:
            LOGGER.exception(
                "Failed to process local WSS message: origin=%s path=%s remote=%s",
                origin,
                request_path,
                remote_address,
            )

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

    def _resolve_request_origin(self, websocket: Any) -> str | None:
        headers = self._resolve_request_headers(websocket)
        if headers is None:
            return None

        for header_name in ("Origin", "origin"):
            try:
                header_value = headers.get(header_name)
            except AttributeError:
                header_value = headers.get(header_name)
            if header_value:
                return str(header_value)

        return None

    def _resolve_request_headers(self, websocket: Any) -> Any | None:
        request = getattr(websocket, "request", None)
        if request is not None:
            request_headers = getattr(request, "headers", None)
            if request_headers is not None:
                return request_headers

        request_headers = getattr(websocket, "request_headers", None)
        if request_headers is not None:
            return request_headers

        return None

    def _resolve_remote_address(self, websocket: Any) -> str | None:
        remote_address = getattr(websocket, "remote_address", None)
        if remote_address is None:
            return None

        if isinstance(remote_address, tuple) and remote_address:
            return ":".join(str(part) for part in remote_address if part is not None)

        return str(remote_address)


def _format_command_label(plugin: str | None, name: str) -> str:
    if plugin:
        return f"{plugin}/{name}"
    return name
