from __future__ import annotations

import asyncio
import logging

import aiohttp

from client.bootstrap.config import AppConfig
from client.integrations.eimzo_api import EimzoApiClient
from client.system.account import resolve_account_name
from client.system.certificates import maintain_localhost_certificate, resolve_server_certificate
from client.transport.websocket.server import WebSocketProxyServer

LOGGER = logging.getLogger(__name__)


async def run_app(config: AppConfig) -> None:
    account_name = resolve_account_name(config.account_name_override)
    timeout = aiohttp.ClientTimeout(total=config.http_timeout_seconds)
    server_certificate = resolve_server_certificate(config)
    certificate_rotation_event = asyncio.Event()
    certificate_task: asyncio.Task[None] | None = None

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

    LOGGER.info("Using account name for x_account_name header: %s", account_name)

    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            endpoint_proxy = EimzoApiClient(
                session=session,
                api_base_url=config.api_eimzo_url,
                api_path_prefix=config.api_eimzo_path_prefix,
                account_name=account_name,
                api_ca_cert_path=config.api_eimzo_ca_cert_path,
                send_account_header=config.api_eimzo_send_account_header,
            )
            websocket_server = WebSocketProxyServer(
                config=config,
                endpoint_proxy=endpoint_proxy,
                server_cert_path=server_certificate.cert_path,
                server_key_path=server_certificate.key_path,
                certificate_rotation_event=certificate_rotation_event,
            )
            await websocket_server.run_forever()
    finally:
        if certificate_task is not None:
            certificate_task.cancel()
            await asyncio.gather(certificate_task, return_exceptions=True)
