from __future__ import annotations

from dataclasses import dataclass
import logging
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
LOGGER = logging.getLogger(__name__)


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
        api_path_prefix: str,
        account_name: str,
        api_ca_cert_path: Path | None = None,
        send_account_header: bool = True,
    ) -> None:
        self._session = session
        self._api_base_url = api_base_url.rstrip("/")
        self._api_path_prefix = api_path_prefix
        self._account_name = account_name
        self._api_ca_cert_path = api_ca_cert_path
        self._send_account_header = send_account_header

    async def forward(self, command: ProxyCommand) -> ProxyResponse:
        endpoint_url = self._build_endpoint_url(command.plugin, command.name)
        headers: dict[str, str] = {}
        if self._send_account_header:
            headers["x-account-name"] = self._account_name

        request_kwargs: dict[str, Any] = {"headers": headers}
        if self._api_ca_cert_path is not None:
            request_kwargs["ssl"] = build_client_ssl_context(self._api_ca_cert_path)

        method = "GET"
        if command.has_arguments:
            method = "POST"
            request_kwargs["json"] = command.arguments

        LOGGER.info("Forwarding %s %s", method, endpoint_url)
        async with self._session.request(method, endpoint_url, **request_kwargs) as response:
            body = await response.read()
            LOGGER.info(
                "Received API response %s %s for %s %s",
                response.status,
                response.reason,
                method,
                endpoint_url,
            )
            if response.status >= 400:
                LOGGER.warning(
                    "API error response body for %s %s: %s",
                    method,
                    endpoint_url,
                    _format_body_for_log(body=body, charset=response.charset),
                )
            return ProxyResponse(
                body=body,
                content_type=response.content_type,
                charset=response.charset,
            )

    def _build_endpoint_url(self, plugin: str | None, name: str) -> str:
        segments = [self._api_base_url]
        if self._api_path_prefix:
            segments.append(self._api_path_prefix.strip("/"))
        if plugin:
            segments.append(str(plugin).strip("/"))
        segments.append(str(name).strip("/"))
        return "/".join(segment for segment in segments if segment)


def _format_body_for_log(*, body: bytes, charset: str | None) -> str:
    if not body:
        return "<empty>"

    encoding = charset or "utf-8"
    try:
        text = body.decode(encoding)
    except UnicodeDecodeError:
        text = body.decode("utf-8", errors="replace")

    text = " ".join(text.split())
    if len(text) > 1000:
        return f"{text[:1000]}..."
    return text
