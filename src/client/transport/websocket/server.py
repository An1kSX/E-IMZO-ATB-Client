from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
import logging
from pathlib import Path
from typing import Any

from websockets.exceptions import ConnectionClosed
from websockets.legacy.server import serve as legacy_websocket_serve

from client.bootstrap.config import AppConfig
from client.integrations.eimzo_api import EimzoApiClient
from client.system.certificates import build_websocket_server_ssl_context
from client.transport.websocket.messages import parse_proxy_command

LOGGER = logging.getLogger(__name__)
_USER_ACTION_LOG_EXTRA = {"user_action": True}
_CLOSE_CODE_NORMAL_CLOSURE = 1000
_CLOSE_CODE_GOING_AWAY = 1001
_CLOSE_CODE_POLICY_VIOLATION = 1008
_REQUEST_COMPLETED_CLOSE_REASON = "Request completed"
_SERVER_RELOAD_CLOSE_REASON = "Server certificate reloaded"
_UNEXPECTED_PATH_CLOSE_REASON = "Unexpected WebSocket path"
_LEGACY_SERVER_CLOSE_REASON = "Server closed"


class WebSocketPortInUseError(RuntimeError):
    def __init__(
        self,
        *,
        host: str,
        port: int,
        error: OSError,
        endpoint_label: str = "WSS",
    ) -> None:
        super().__init__(f"WebSocket {endpoint_label} port {host}:{port} is already in use: {error}")
        self.host = host
        self.port = port
        self.endpoint_label = endpoint_label


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
            except WebSocketPortInUseError:
                raise
            except OSError as error:
                if _is_address_in_use_error(error):
                    raise WebSocketPortInUseError(
                        host=self._config.ws_host,
                        port=self._config.ws_port,
                        error=error,
                    ) from error
                LOGGER.exception(
                    "Local WebSocket server failed. Restarting in %.1f seconds.",
                    self._config.server_retry_delay_seconds,
                )
                await asyncio.sleep(self._config.server_retry_delay_seconds)
            except Exception:
                LOGGER.exception(
                    "Local WebSocket server failed. Restarting in %.1f seconds.",
                    self._config.server_retry_delay_seconds,
                )
                await asyncio.sleep(self._config.server_retry_delay_seconds)

    async def _serve_until_certificate_rotation(self) -> None:
        self._certificate_rotation_event.clear()
        ssl_context = build_websocket_server_ssl_context(
            cert_path=self._server_cert_path,
            key_path=self._server_key_path,
        )

        insecure_port = self._resolve_insecure_port()
        async with AsyncExitStack() as stack:
            secure_server = await self._start_listener(
                stack=stack,
                port=self._config.ws_port,
                ssl_context=ssl_context,
                endpoint_label="WSS",
            )
            LOGGER.info("Local WSS server is listening on %s", self._config.websocket_bind_url())
            insecure_server = None
            insecure_bind_url: str | None = None
            if insecure_port is not None:
                insecure_server = await self._start_listener(
                    stack=stack,
                    port=insecure_port,
                    ssl_context=None,
                    endpoint_label="WS",
                )
                insecure_bind_url = self._resolve_insecure_bind_url(insecure_port)
                LOGGER.info("Local WS server is listening on %s", insecure_bind_url)

            await self._certificate_rotation_event.wait()
            LOGGER.info("Reloading local WebSocket servers to apply renewed certificate.")
            self._close_server_with_reason(
                secure_server,
                code=_CLOSE_CODE_GOING_AWAY,
                reason=_SERVER_RELOAD_CLOSE_REASON,
            )
            await secure_server.wait_closed()
            if insecure_server is not None:
                LOGGER.info("Reloading local WS server on %s.", insecure_bind_url)
                self._close_server_with_reason(
                    insecure_server,
                    code=_CLOSE_CODE_GOING_AWAY,
                    reason=_SERVER_RELOAD_CLOSE_REASON,
                )
                await insecure_server.wait_closed()

    async def _start_listener(
        self,
        *,
        stack: AsyncExitStack,
        port: int,
        ssl_context: Any | None,
        endpoint_label: str,
    ) -> Any:
        try:
            return await stack.enter_async_context(
                legacy_websocket_serve(
                    self._handle_connection,
                    host=self._config.ws_host,
                    port=port,
                    ssl=ssl_context,
                    ping_interval=self._config.ws_ping_interval_seconds,
                    ping_timeout=self._config.ws_ping_timeout_seconds,
                )
            )
        except OSError as error:
            if _is_address_in_use_error(error):
                raise WebSocketPortInUseError(
                    host=self._config.ws_host,
                    port=port,
                    error=error,
                    endpoint_label=endpoint_label,
                ) from error
            raise

    def _close_server_with_reason(self, server: Any, *, code: int, reason: str) -> None:
        try:
            server.close(code=code, reason=reason)
        except TypeError:
            # websockets.legacy server API doesn't accept close code/reason kwargs.
            server.close()
            LOGGER.debug(
                "Legacy WebSocket server close called without explicit code/reason. "
                "requested_code=%s requested_reason=%s fallback_reason=%s",
                code,
                reason,
                _LEGACY_SERVER_CLOSE_REASON,
            )

    def _resolve_insecure_port(self) -> int | None:
        raw_value = getattr(self._config, "ws_insecure_port", None)
        if raw_value is None:
            return None

        try:
            port = int(raw_value)
        except (TypeError, ValueError):
            LOGGER.warning("Ignoring invalid WS insecure port value: %r", raw_value)
            return None

        if port <= 0:
            return None
        return port

    def _resolve_insecure_bind_url(self, port: int) -> str:
        bind_url_factory = getattr(self._config, "websocket_insecure_bind_url", None)
        if callable(bind_url_factory):
            bind_url = bind_url_factory()
            if bind_url:
                return bind_url
        return f"ws://{self._config.ws_host}:{port}{self._config.ws_path}"

    async def _handle_connection(self, websocket: Any, path: str | None = None) -> None:
        request_path = self._resolve_request_path(websocket, path)
        origin = self._resolve_request_origin(websocket)
        remote_address = self._resolve_remote_address(websocket)
        if not self._config.matches_websocket_path(request_path):
            LOGGER.warning(
                "Rejected WebSocket connection on unexpected path: path=%s origin=%s remote=%s",
                request_path,
                origin,
                remote_address,
                extra=_USER_ACTION_LOG_EXTRA,
            )
            await websocket.close(
                code=_CLOSE_CODE_POLICY_VIOLATION,
                reason=_UNEXPECTED_PATH_CLOSE_REASON,
            )
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
                return
        except ConnectionClosed as error:
            LOGGER.info(
                "Local WebSocket connection closed: path=%s origin=%s remote=%s received_close=%s sent_close=%s",
                request_path,
                origin,
                remote_address,
                _format_close_frame(getattr(error, "rcvd", None)),
                _format_close_frame(getattr(error, "sent", None)),
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
                "Received WebSocket command: command=%s has_arguments=%s origin=%s path=%s remote=%s",
                command_label,
                command.has_arguments,
                origin,
                request_path,
                remote_address,
                extra=_USER_ACTION_LOG_EXTRA,
            )
            response = await self._endpoint_proxy.forward(command, origin=origin)
            await websocket.send(response.to_websocket_payload())
            await websocket.close(
                code=_CLOSE_CODE_NORMAL_CLOSURE,
                reason=_REQUEST_COMPLETED_CLOSE_REASON,
            )
        except Exception:
            LOGGER.exception(
                "Failed to process local WebSocket message: origin=%s path=%s remote=%s",
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


def _format_close_frame(close_frame: Any | None) -> str:
    if close_frame is None:
        return "none"

    code = getattr(close_frame, "code", None)
    reason = getattr(close_frame, "reason", "")
    if reason:
        return f"{code}:{reason}"
    return str(code)


def _is_address_in_use_error(error: OSError) -> bool:
    winerror = getattr(error, "winerror", None)
    if winerror == 10048:
        return True

    if error.errno in {48, 98, 10048}:
        return True

    message = str(error).casefold()
    return (
        "address already in use" in message
        or "only one usage of each socket address" in message
        or "одно использование адреса сокета" in message
    )
