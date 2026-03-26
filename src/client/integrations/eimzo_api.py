from __future__ import annotations

from dataclasses import dataclass
import json
import logging
from pathlib import Path
from typing import Any

import aiohttp

from client.domain.commands import ProxyCommand
from client.domain.key_identity_store import KeyIdentityStore
from client.system.certificates import build_client_ssl_context

_TEXTUAL_CONTENT_TYPES = {
    "application/javascript",
    "application/json",
    "application/problem+json",
    "application/xml",
}
_PFX_PLUGIN_NAME = "pfx"
_LOAD_KEY_COMMAND_NAME = "load_key"
_PKCS7_PLUGIN_NAME = "pkcs7"
_CREATE_PKCS7_COMMAND_NAME = "create_pkcs7"
_VERIFY_PASSWORD_COMMAND_NAME = "verify_password"
_CHANGE_PASSWORD_COMMAND_NAME = "change_password"
_IDENTITY_ARGUMENT_KEY_ID_INDEXES: dict[tuple[str | None, str], int] = {
    (_PKCS7_PLUGIN_NAME, _CREATE_PKCS7_COMMAND_NAME): 1,
    (_PFX_PLUGIN_NAME, _VERIFY_PASSWORD_COMMAND_NAME): 0,
    (_PFX_PLUGIN_NAME, _CHANGE_PASSWORD_COMMAND_NAME): 0,
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
        key_identity_store: KeyIdentityStore | None = None,
    ) -> None:
        self._session = session
        self._api_base_url = api_base_url.rstrip("/")
        self._api_path_prefix = api_path_prefix
        self._account_name = account_name
        self._api_ca_cert_path = api_ca_cert_path
        self._send_account_header = send_account_header
        self._key_identity_store = key_identity_store or KeyIdentityStore()

    async def forward(self, command: ProxyCommand) -> ProxyResponse:
        endpoint_url = self._build_endpoint_url(command.plugin, command.name)
        key_name = _extract_key_name_from_load_key_command(command)
        request_arguments = self._build_request_arguments(command)
        headers: dict[str, str] = {}
        if self._send_account_header:
            headers["x-account-name"] = self._account_name

        request_kwargs: dict[str, Any] = {"headers": headers}
        if self._api_ca_cert_path is not None:
            request_kwargs["ssl"] = build_client_ssl_context(self._api_ca_cert_path)

        method = "GET"
        if command.has_arguments:
            method = "POST"
            request_kwargs["json"] = request_arguments

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

            proxy_response = ProxyResponse(
                body=body,
                content_type=response.content_type,
                charset=response.charset,
            )

        self._remember_key_identity(key_name=key_name, response=proxy_response)
        return proxy_response

    def _build_endpoint_url(self, plugin: str | None, name: str) -> str:
        segments = [self._api_base_url]
        if self._api_path_prefix:
            segments.append(self._api_path_prefix.strip("/"))
        if plugin:
            segments.append(str(plugin).strip("/"))
        segments.append(str(name).strip("/"))
        return "/".join(segment for segment in segments if segment)

    def get_identity_by_key_id(self, key_id: str) -> str | None:
        return self._key_identity_store.get(key_id)

    def _remember_key_identity(self, *, key_name: str | None, response: ProxyResponse) -> None:
        if key_name is None:
            return

        key_id = _extract_key_id_from_response(response.body, charset=response.charset)
        if key_id is None:
            return

        identity = self._key_identity_store.remember(key_id=key_id, key_name=key_name)
        if identity is None:
            LOGGER.warning("Could not extract INN/PINFL from key name %r for keyId %s", key_name, key_id)
            return

        LOGGER.info("Stored keyId to INN/PINFL mapping: %s -> %s", key_id, identity)

    def _build_request_arguments(self, command: ProxyCommand) -> Any:
        arguments = command.arguments
        if not command.has_arguments:
            return arguments

        if not isinstance(arguments, (list, tuple)):
            return arguments

        key_id = _extract_key_id_from_identity_command(command=command, arguments=arguments)
        if key_id is None:
            return arguments

        command_label = _format_command_label(plugin=command.plugin, name=command.name)
        identity = self._key_identity_store.get(key_id)
        if identity is None:
            LOGGER.warning("No stored INN/PINFL found for keyId %s during %s", key_id, command_label)
            return arguments

        request_arguments = list(arguments)
        if request_arguments and request_arguments[-1] == identity:
            return request_arguments

        request_arguments.append(identity)
        LOGGER.info("Added INN/PINFL %s to %s arguments for keyId %s", identity, command_label, key_id)
        return request_arguments


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


def _extract_key_name_from_load_key_command(command: ProxyCommand) -> str | None:
    if command.plugin != _PFX_PLUGIN_NAME or command.name != _LOAD_KEY_COMMAND_NAME:
        return None

    arguments = command.arguments
    if isinstance(arguments, (list, tuple)) and len(arguments) >= 3:
        key_name = arguments[2]
        if isinstance(key_name, str) and key_name.strip():
            return key_name.strip()

    return None


def _extract_key_id_from_identity_command(*, command: ProxyCommand, arguments: list[Any] | tuple[Any, ...]) -> str | None:
    key_id_index = _IDENTITY_ARGUMENT_KEY_ID_INDEXES.get((command.plugin, command.name))
    if key_id_index is None or len(arguments) <= key_id_index:
        return None

    key_id = arguments[key_id_index]
    if not isinstance(key_id, str) or not key_id.strip():
        return None

    return key_id.strip()


def _format_command_label(*, plugin: str | None, name: str) -> str:
    if plugin:
        return f"{plugin}/{name}"
    return name


def _extract_key_id_from_response(body: bytes, *, charset: str | None) -> str | None:
    if not body:
        return None

    encoding = charset or "utf-8"
    try:
        payload = json.loads(body.decode(encoding))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None

    if isinstance(payload, str) and payload.strip():
        return payload.strip()

    if isinstance(payload, dict):
        key_id = payload.get("keyId") or payload.get("key_id")
        if isinstance(key_id, str) and key_id.strip():
            return key_id.strip()

    return None
