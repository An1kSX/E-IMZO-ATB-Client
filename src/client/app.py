from __future__ import annotations

import asyncio
import logging

import aiohttp

from client.bootstrap.config import AppConfig
from client.integrations.eimzo_api import EimzoApiClient
from client.system.account import resolve_account_name
from client.system.certificates import ensure_localhost_certificate, maintain_localhost_certificate
from client.transport.websocket.server import WebSocketProxyServer

LOGGER = logging.getLogger(__name__)


async def run_app(config: AppConfig) -> None:
    account_name = resolve_account_name(config.account_name_override)
    timeout = aiohttp.ClientTimeout(total=config.http_timeout_seconds)
    local_certificate = ensure_localhost_certificate(config)
    certificate_rotation_event = asyncio.Event()
    certificate_task = asyncio.create_task(
        maintain_localhost_certificate(config, certificate_rotation_event)
    )

    if local_certificate.renewed:
        LOGGER.info("Local certificate for 127.0.0.1 was created or renewed: %s", local_certificate.cert_path)
    else:
        LOGGER.info("Using local certificate for 127.0.0.1: %s", local_certificate.cert_path)

    LOGGER.info("Using account name for x_account_name header: %s", account_name)

    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            endpoint_proxy = EimzoApiClient(
                session=session,
                api_base_url=config.api_eimzo_url,
                account_name=account_name,
                local_api_cert_path=local_certificate.cert_path if config.use_local_api_ssl_certificate() else None,
            )
            websocket_server = WebSocketProxyServer(
                config=config,
                endpoint_proxy=endpoint_proxy,
                server_cert_path=local_certificate.cert_path,
                server_key_path=local_certificate.key_path,
                certificate_rotation_event=certificate_rotation_event,
            )
            await websocket_server.run_forever()
    finally:
        certificate_task.cancel()
        await asyncio.gather(certificate_task, return_exceptions=True)
