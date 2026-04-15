from __future__ import annotations

import asyncio
import logging

import aiohttp

from client.bootstrap.config import AppConfig
from client.integrations.eimzo_api import EimzoApiClient
from client.system.account import resolve_account_name
from client.system.autostart import disable_known_eimzo_autostart
from client.system.certificates import maintain_localhost_certificate, resolve_server_certificate
from client.system.eimzo_process import (
    find_listening_process_by_port,
    is_eimzo_process,
    is_port_in_use,
    terminate_related_eimzo_processes,
    terminate_process_by_pid,
)
from client.transport.websocket.server import WebSocketPortInUseError, WebSocketProxyServer
from client.ui import show_info_message
from client.ui.prompts import PromptService, TkPromptService

LOGGER = logging.getLogger(__name__)
_PORT_CONFLICT_LOGGER = logging.getLogger("client.port_conflict")


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
                        LOGGER.info(
                            "Startup was cancelled because WebSocket port %s is already in use.",
                            error.port,
                        )
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
    listening_process = find_listening_process_by_port(port=conflict.port)
    _PORT_CONFLICT_LOGGER.info(
        "Port conflict flow started. port=%s initial_process=%s",
        conflict.port,
        listening_process,
    )
    if listening_process is None:
        LOGGER.error(
            "WebSocket port %s is already in use, but process owner could not be determined.",
            conflict.port,
        )
        _PORT_CONFLICT_LOGGER.error(
            "Port conflict flow aborted because process owner could not be determined. port=%s",
            conflict.port,
        )
        show_info_message(
            title="Порт уже занят",
            message=(
                f"Порт {conflict.port} уже занят, но определить процесс не удалось.\n\n"
                "Закройте приложение, которое использует этот порт, и попробуйте снова."
            ),
        )
        return False

    if not is_eimzo_process(listening_process):
        LOGGER.error(
            "WebSocket port %s is already in use by %s (PID %s).",
            conflict.port,
            listening_process.name,
            listening_process.pid,
        )
        _PORT_CONFLICT_LOGGER.warning(
            "Port conflict belongs to a non-E-IMZO process. process=%s",
            listening_process,
        )
        show_info_message(
            title="Порт уже занят",
            message=(
                f"Порт {conflict.port} уже занят процессом {listening_process.name} (PID {listening_process.pid}).\n\n"
                "Закройте этот процесс и попробуйте снова."
            ),
        )
        return False

    while True:
        resolution = await prompt_service.resolve_port_conflict(
            process_name=listening_process.name,
            port=conflict.port,
        )
        _PORT_CONFLICT_LOGGER.info(
            "Port conflict dialog resolved. process=%s terminate_process=%s remove_from_autostart=%s",
            listening_process,
            resolution.terminate_process,
            resolution.remove_from_autostart,
        )
        if not resolution.terminate_process:
            _PORT_CONFLICT_LOGGER.info("User cancelled the port conflict flow.")
            return False

        if resolution.remove_from_autostart:
            removed_autostart_entries = disable_known_eimzo_autostart()
            _PORT_CONFLICT_LOGGER.info(
                "Requested E-IMZO autostart removal. removed_entries=%s",
                removed_autostart_entries,
            )
            if removed_autostart_entries == 0:
                LOGGER.warning("Could not find E-IMZO auto-start entries to remove.")
                show_info_message(
                    title="Автозагрузка E-IMZO не найдена",
                    message=(
                        "Не удалось найти запись автозагрузки E-IMZO в стандартных местах Windows.\n\n"
                        "Возможно, она настроена через другой механизм и её нужно отключить вручную."
                    ),
                )

        stopped = terminate_related_eimzo_processes(listening_process=listening_process)
        _PORT_CONFLICT_LOGGER.info(
            "terminate_related_eimzo_processes finished. process=%s stopped=%s",
            listening_process,
            stopped,
        )
        if not stopped:
            stopped = terminate_process_by_pid(pid=listening_process.pid)
            _PORT_CONFLICT_LOGGER.info(
                "Direct terminate_process_by_pid fallback finished. pid=%s stopped=%s",
                listening_process.pid,
                stopped,
            )
        if stopped:
            port_released = await _wait_for_port_release(port=conflict.port)
            _PORT_CONFLICT_LOGGER.info(
                "Port release wait finished. port=%s released=%s",
                conflict.port,
                port_released,
            )
            if not port_released:
                LOGGER.warning(
                    "Requested E-IMZO shutdown succeeded for PID %s, but WebSocket port %s is still busy.",
                    listening_process.pid,
                    conflict.port,
                )
                refreshed_process = find_listening_process_by_port(port=conflict.port)
                _PORT_CONFLICT_LOGGER.warning(
                    "Port is still busy after stop attempt. refreshed_process=%s",
                    refreshed_process,
                )
                if refreshed_process is not None and is_eimzo_process(refreshed_process):
                    show_info_message(
                        title="E-IMZO всё ещё запущен",
                        message=(
                            f"После попытки закрытия процесс {refreshed_process.name} всё ещё удерживает порт {conflict.port}.\n\n"
                            "Попробуйте ещё раз или закройте E-IMZO вручную."
                        ),
                    )
                    listening_process = refreshed_process
                    continue

                if refreshed_process is None:
                    show_info_message(
                        title="Порт всё ещё занят",
                        message=(
                            f"После закрытия E-IMZO порт {conflict.port} всё ещё не освободился.\n\n"
                            "Попробуйте запустить клиент ещё раз через несколько секунд."
                        ),
                    )
                else:
                    show_info_message(
                        title="Порт всё ещё занят",
                        message=(
                            f"После закрытия E-IMZO порт {conflict.port} всё ещё занят процессом "
                            f"{refreshed_process.name} (PID {refreshed_process.pid}).\n\n"
                            "Закройте этот процесс и попробуйте снова."
                        ),
                    )
                listening_process = refreshed_process or listening_process
                continue

            LOGGER.info(
                "Terminated %s (PID %s) and will retry WebSocket startup.",
                listening_process.name,
                listening_process.pid,
            )
            _PORT_CONFLICT_LOGGER.info(
                "Port conflict flow succeeded. Retrying WebSocket startup. process=%s",
                listening_process,
            )
            return True

        LOGGER.error(
            "User approved stopping %s, but process PID %s could not be terminated.",
            listening_process.name,
            listening_process.pid,
        )
        _PORT_CONFLICT_LOGGER.error(
            "Process stop attempt failed. process=%s",
            listening_process,
        )
        show_info_message(
            title="Не удалось закрыть E-IMZO",
            message=(
                f"Не удалось закрыть процесс {listening_process.name} (PID {listening_process.pid}).\n\n"
                "Попробуйте закрыть E-IMZO вручную или повторите попытку."
            ),
        )
        refreshed_process = find_listening_process_by_port(port=conflict.port)
        _PORT_CONFLICT_LOGGER.info(
            "Refreshed process after failed stop attempt. refreshed_process=%s",
            refreshed_process,
        )
        if refreshed_process is None:
            await asyncio.sleep(1.0)
            _PORT_CONFLICT_LOGGER.info("No refreshed process found after failed stop attempt; continuing loop.")
            continue
        listening_process = refreshed_process


async def _wait_for_port_release(
    *,
    port: int,
    timeout_seconds: float = 5.0,
    poll_interval_seconds: float = 0.25,
) -> bool:
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    _PORT_CONFLICT_LOGGER.info(
        "Waiting for port release. port=%s timeout_seconds=%s poll_interval_seconds=%s",
        port,
        timeout_seconds,
        poll_interval_seconds,
    )
    while True:
        if not is_port_in_use(port=port):
            _PORT_CONFLICT_LOGGER.info("Port is no longer in use. port=%s", port)
            return True
        if asyncio.get_running_loop().time() >= deadline:
            _PORT_CONFLICT_LOGGER.warning("Port release wait timed out. port=%s", port)
            return False
        await asyncio.sleep(poll_interval_seconds)
