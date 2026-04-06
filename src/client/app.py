from __future__ import annotations

import asyncio
import logging

import aiohttp

from client.bootstrap.config import AppConfig
from client.integrations.eimzo_api import EimzoApiClient
from client.system.account import resolve_account_name
from client.system.autostart import disable_windows_run_entries_by_command_fragment
from client.system.certificates import maintain_localhost_certificate, resolve_server_certificate
from client.system.eimzo_process import (
    find_listening_process_by_port,
    is_eimzo_process_name,
    terminate_process_by_pid,
)
from client.transport.websocket.server import WebSocketPortInUseError, WebSocketProxyServer
from client.ui.prompts import PromptService, TkPromptService

LOGGER = logging.getLogger(__name__)


async def run_app(config: AppConfig) -> None:
    account_name = resolve_account_name(config.account_name_override)
    timeout = aiohttp.ClientTimeout(total=config.http_timeout_seconds)
    server_certificate = resolve_server_certificate(config)
    certificate_rotation_event = asyncio.Event()
    certificate_task: asyncio.Task[None] | None = None
    prompt_service = TkPromptService()

    if server_certificate.managed and server_certificate.renewed:
        LOGGER.info(
            "Local certificate for 127.0.0.1 was created or renewed: %s",
            server_certificate.cert_path,
        )
    elif server_certificate.managed:
        LOGGER.info("Using local certificate for 127.0.0.1: %s", server_certificate.cert_path)
    else:
        LOGGER.info("Using configured WSS server certificate: %s", server_certificate.cert_path)

    if server_certificate.managed:
        certificate_task = asyncio.create_task(
            maintain_localhost_certificate(config, certificate_rotation_event)
        )

    if config.api_eimzo_ca_cert_path is not None:
        LOGGER.info("Using configured CA certificate for E-IMZO API: %s", config.api_eimzo_ca_cert_path)
    if server_certificate.managed and server_certificate.ca_cert_path is not None:
        LOGGER.info("Using managed local root CA for WSS server: %s", server_certificate.ca_cert_path)

    LOGGER.info("Using account name for E-IMZO authentication: %s", account_name)

    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            endpoint_proxy = EimzoApiClient(
                session=session,
                api_base_url=config.api_eimzo_url,
                api_path_prefix=config.api_eimzo_path_prefix,
                account_name=account_name,
                api_ca_cert_path=config.api_eimzo_ca_cert_path,
                send_account_header=config.api_eimzo_send_account_header,
                prompt_service=prompt_service,
            )
            startup_authenticated = await endpoint_proxy.ensure_authenticated()
            if startup_authenticated:
                LOGGER.info("Validated E-IMZO JWT session during startup.")
            else:
                LOGGER.warning(
                    "E-IMZO startup authentication was cancelled. "
                    "The password prompt will appear again on the first protected request."
                )
            websocket_server = WebSocketProxyServer(
                config=config,
                endpoint_proxy=endpoint_proxy,
                server_cert_path=server_certificate.cert_path,
                server_key_path=server_certificate.key_path,
                certificate_rotation_event=certificate_rotation_event,
            )
            while True:
                try:
                    await websocket_server.run_forever()
                    return
                except WebSocketPortInUseError as error:
                    should_retry = await _resolve_port_conflict(
                        config=config,
                        prompt_service=prompt_service,
                        conflict=error,
                    )
                    if not should_retry:
                        LOGGER.info("Startup was cancelled because WSS port %s is already in use.", error.port)
                        return
    finally:
        prompt_service.close()
        if certificate_task is not None:
            certificate_task.cancel()
            await asyncio.gather(certificate_task, return_exceptions=True)


async def _resolve_port_conflict(
    *,
    config: AppConfig,
    prompt_service: PromptService,
    conflict: WebSocketPortInUseError,
) -> bool:
    listening_process = find_listening_process_by_port(port=config.ws_port)
    if listening_process is None:
        LOGGER.error("WSS port %s is already in use, but process owner could not be determined.", conflict.port)
        return False

    if not is_eimzo_process_name(listening_process.name):
        LOGGER.error(
            "WSS port %s is already in use by %s (PID %s).",
            conflict.port,
            listening_process.name,
            listening_process.pid,
        )
        return False

    resolution = await prompt_service.resolve_port_conflict(
        process_name=listening_process.name,
        port=conflict.port,
    )
    if not resolution.terminate_process:
        return False

    if resolution.remove_from_autostart:
        disable_windows_run_entries_by_command_fragment(fragment="e-imzo.exe")

    stopped = terminate_process_by_pid(pid=listening_process.pid)
    if not stopped:
        LOGGER.error(
            "User approved stopping %s, but process PID %s could not be terminated.",
            listening_process.name,
            listening_process.pid,
        )
        return False

    LOGGER.info("Terminated %s (PID %s) and will retry WSS startup.", listening_process.name, listening_process.pid)
    return True
