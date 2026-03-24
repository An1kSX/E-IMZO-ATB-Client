from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import aiohttp

from client.domain.commands import ProxyCommand
from client.system.certificates import build_client_ssl_context

_TEXTUAL_CONTENT_TYPES = {
    "application/javascript",
    "application/json",
    "application/problem+json",
    "application/xml",
}


@dataclass(frozen=True, slots=True)
class ProxyResponse:
    body: bytes
    content_type: str | None
    charset: str | None

    def to_websocket_payload(self) -> str | bytes:
        encoding = self.charset or "utf-8"
        if self._is_textual():
            try:
                return self.body.decode(encoding)
            except UnicodeDecodeError:
                return self.body
        return self.body

    def _is_textual(self) -> bool:
        if self.content_type is None:
            return False
        return self.content_type.startswith("text/") or self.content_type in _TEXTUAL_CONTENT_TYPES


class EimzoApiClient:
    def __init__(
        self,
        *,
        session: aiohttp.ClientSession,
        api_base_url: str,
        account_name: str,
        api_ca_cert_path: Path | None = None,
    ) -> None:
        self._session = session
        self._api_base_url = api_base_url.rstrip("/")
        self._account_name = account_name
        self._api_ca_cert_path = api_ca_cert_path

    async def forward(self, command: ProxyCommand) -> ProxyResponse:
        endpoint_url = self._build_endpoint_url(command.plugin, command.name)
        headers = {"x_account_name": self._account_name}

        request_kwargs: dict[str, Any] = {"headers": headers}
        if self._api_ca_cert_path is not None:
            request_kwargs["ssl"] = build_client_ssl_context(self._api_ca_cert_path)

        method = "GET"
        if command.has_arguments:
            method = "POST"
            request_kwargs["json"] = command.arguments

        async with self._session.request(method, endpoint_url, **request_kwargs) as response:
            body = await response.read()
            return ProxyResponse(
                body=body,
                content_type=response.content_type,
                charset=response.charset,
            )

    def _build_endpoint_url(self, plugin: str, name: str) -> str:
        return f"{self._api_base_url}/{plugin}/{name}"
