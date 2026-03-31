from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass
import json
import logging
from pathlib import Path
import time
from typing import Any, Callable

import aiohttp

from client.domain.commands import ProxyCommand
from client.domain.key_identity_store import KeyIdentityStore
from client.system.certificates import build_client_ssl_context
from client.ui.prompts import PromptService, TkPromptService

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
_AUTH_PLUGIN_NAME = "auth"
_AUTH_LOGIN_COMMAND_NAME = "login"
_AUTH_INVALID_STATUS_CODES = {400, 401, 403}
_ACCESS_TOKEN_REFRESH_LEEWAY_SECONDS = 30.0
_MISSING = object()
_IDENTITY_ARGUMENT_KEY_ID_INDEXES: dict[tuple[str | None, str], int] = {
    (_PKCS7_PLUGIN_NAME, _CREATE_PKCS7_COMMAND_NAME): 1,
    (_PFX_PLUGIN_NAME, _VERIFY_PASSWORD_COMMAND_NAME): 0,
    (_PFX_PLUGIN_NAME, _CHANGE_PASSWORD_COMMAND_NAME): 0,
}
LOGGER = logging.getLogger(__name__)
_USER_ACTION_LOG_EXTRA = {"user_action": True}


@dataclass(frozen=True, slots=True)
class ProxyResponse:
    body: bytes
    content_type: str | None
    charset: str | None

    @classmethod
    def from_json(cls, payload: Any) -> "ProxyResponse":
        return cls(
            body=json.dumps(payload).encode("utf-8"),
            content_type="application/json",
            charset="utf-8",
        )

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


@dataclass(frozen=True, slots=True)
class HttpProxyResponse:
    status: int
    reason: str
    proxy_response: ProxyResponse


@dataclass(frozen=True, slots=True)
class PreparedRequest:
    arguments: Any
    sensitive_identity: str | None = None


@dataclass(frozen=True, slots=True)
class AccessToken:
    value: str
    expires_at: float | None

    def is_valid(self, *, now: float) -> bool:
        if self.expires_at is None:
            return True
        return (now + _ACCESS_TOKEN_REFRESH_LEEWAY_SECONDS) < self.expires_at


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
        prompt_service: PromptService | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._session = session
        self._api_base_url = api_base_url.rstrip("/")
        self._api_path_prefix = api_path_prefix
        self._account_name = account_name
        self._api_ca_cert_path = api_ca_cert_path
        self._send_account_header = send_account_header
        self._key_identity_store = key_identity_store or KeyIdentityStore()
        self._prompt_service = prompt_service or TkPromptService()
        self._clock = clock or time.time
        self._access_token: AccessToken | None = None
        self._auth_lock = asyncio.Lock()

    async def ensure_authenticated(self) -> bool:
        token = await self._ensure_access_token(
            reason="Введите пароль для входа в E-IMZO перед началом работы приложения.",
        )
        return token is not None

    async def forward(self, command: ProxyCommand) -> ProxyResponse:
        endpoint_url = self._build_endpoint_url(command.plugin, command.name)
        key_name = _extract_key_name_from_load_key_command(command)
        prepared_request = self._build_request(command)
        command_label = _format_command_label(plugin=command.plugin, name=command.name)

        if prepared_request.sensitive_identity is not None:
            approved = await self._prompt_service.confirm_sensitive_operation(
                command=command,
                identity=prepared_request.sensitive_identity,
            )
            if not approved:
                LOGGER.info(
                    "User cancelled sensitive operation %s for identity %s",
                    command_label,
                    prepared_request.sensitive_identity,
                    extra=_USER_ACTION_LOG_EXTRA,
                )
                return _cancelled_proxy_response()

        token = await self._ensure_access_token(
            reason="Введите пароль для получения доступа к E-IMZO API.",
        )
        if token is None:
            return _cancelled_proxy_response()

        response = await self._forward_with_token(
            command=command,
            endpoint_url=endpoint_url,
            request_arguments=prepared_request.arguments,
            access_token=token,
        )

        if response.status == 401:
            LOGGER.info("Access token was rejected for %s. Requesting a new password.", command_label)
            self._access_token = None
            token = await self._ensure_access_token(
                force_refresh=True,
                reason="Срок действия сессии истек. Введите пароль повторно.",
            )
            if token is None:
                return _cancelled_proxy_response()

            response = await self._forward_with_token(
                command=command,
                endpoint_url=endpoint_url,
                request_arguments=prepared_request.arguments,
                access_token=token,
            )

        self._remember_key_identity(key_name=key_name, response=response.proxy_response)
        return response.proxy_response

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

    def _build_request(self, command: ProxyCommand) -> PreparedRequest:
        arguments = command.arguments
        if not command.has_arguments:
            return PreparedRequest(arguments=arguments)

        if not isinstance(arguments, (list, tuple)):
            return PreparedRequest(arguments=arguments)

        key_id = _extract_key_id_from_identity_command(command=command, arguments=arguments)
        if key_id is None:
            return PreparedRequest(arguments=arguments)

        command_label = _format_command_label(plugin=command.plugin, name=command.name)
        identity = self._key_identity_store.get(key_id)
        if identity is None:
            LOGGER.warning("No stored INN/PINFL found for keyId %s during %s", key_id, command_label)
            return PreparedRequest(arguments=arguments)

        request_arguments = list(arguments)
        if not request_arguments or request_arguments[-1] != identity:
            request_arguments.append(identity)
            LOGGER.info("Added INN/PINFL %s to %s arguments for keyId %s", identity, command_label, key_id)

        return PreparedRequest(arguments=request_arguments, sensitive_identity=identity)

    async def _forward_with_token(
        self,
        *,
        command: ProxyCommand,
        endpoint_url: str,
        request_arguments: Any,
        access_token: str,
    ) -> HttpProxyResponse:
        method = "GET"
        json_payload: Any = _MISSING
        if command.has_arguments:
            method = "POST"
            json_payload = request_arguments

        headers = {"Authorization": f"Bearer {access_token}"}
        return await self._request(
            method=method,
            endpoint_url=endpoint_url,
            headers=headers,
            json_payload=json_payload,
        )

    async def _ensure_access_token(
        self,
        *,
        reason: str,
        force_refresh: bool = False,
    ) -> str | None:
        async with self._auth_lock:
            if force_refresh:
                self._access_token = None

            cached_token = self._access_token
            if cached_token is not None and cached_token.is_valid(now=self._clock()):
                return cached_token.value

            error_message: str | None = None
            prompt_reason = reason

            while True:
                password = await self._prompt_service.request_password(
                    account_name=self._account_name,
                    reason=prompt_reason,
                    error_message=error_message,
                )
                if password is None:
                    LOGGER.info("User cancelled E-IMZO login prompt.", extra=_USER_ACTION_LOG_EXTRA)
                    return None

                access_token = await self._login(account_name=self._account_name, password=password)
                if access_token is not None:
                    self._access_token = access_token
                    return access_token.value

                error_message = "Неверный пароль или доступ запрещен. Попробуйте снова."
                prompt_reason = "E-IMZO отклонил предыдущую попытку входа."

    async def _login(self, *, account_name: str, password: str) -> AccessToken | None:
        endpoint_url = self._build_endpoint_url(_AUTH_PLUGIN_NAME, _AUTH_LOGIN_COMMAND_NAME)
        response = await self._request(
            method="POST",
            endpoint_url=endpoint_url,
            headers={},
            json_payload={
                "account_name": account_name,
                "password": password,
            },
        )

        if response.status in _AUTH_INVALID_STATUS_CODES:
            LOGGER.warning(
                "E-IMZO login was rejected with %s %s",
                response.status,
                response.reason,
                extra=_USER_ACTION_LOG_EXTRA,
            )
            return None

        if response.status >= 400:
            raise RuntimeError(
                "E-IMZO login failed with "
                f"{response.status} {response.reason}: "
                f"{_format_body_for_log(body=response.proxy_response.body, charset=response.proxy_response.charset)}"
            )

        token_value = _extract_access_token_from_response(
            response.proxy_response.body,
            charset=response.proxy_response.charset,
        )
        if token_value is None:
            raise RuntimeError("E-IMZO login response did not contain a JWT token.")

        expires_at = _extract_jwt_expiration(token_value)
        LOGGER.info("Received JWT token for account %s", account_name)
        return AccessToken(value=token_value, expires_at=expires_at)

    async def _request(
        self,
        *,
        method: str,
        endpoint_url: str,
        headers: dict[str, str],
        json_payload: Any = _MISSING,
    ) -> HttpProxyResponse:
        request_kwargs: dict[str, Any] = {"headers": headers}
        if self._api_ca_cert_path is not None:
            request_kwargs["ssl"] = build_client_ssl_context(self._api_ca_cert_path)
        if json_payload is not _MISSING:
            request_kwargs["json"] = json_payload

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

            return HttpProxyResponse(
                status=response.status,
                reason=response.reason,
                proxy_response=ProxyResponse(
                    body=body,
                    content_type=response.content_type,
                    charset=response.charset,
                ),
            )


def _cancelled_proxy_response() -> ProxyResponse:
    return ProxyResponse.from_json({"success": False})


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


def _extract_key_id_from_identity_command(
    *,
    command: ProxyCommand,
    arguments: list[Any] | tuple[Any, ...],
) -> str | None:
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
    payload = _decode_json_payload(body, charset=charset)
    if payload is None:
        return None

    if isinstance(payload, str) and payload.strip():
        return payload.strip()

    if isinstance(payload, dict):
        key_id = payload.get("keyId") or payload.get("key_id")
        if isinstance(key_id, str) and key_id.strip():
            return key_id.strip()

    return None


def _extract_access_token_from_response(body: bytes, *, charset: str | None) -> str | None:
    payload = _decode_json_payload(body, charset=charset)
    if payload is None:
        text = _decode_text_payload(body, charset=charset)
        return text or None

    if isinstance(payload, str):
        return payload.strip() or None

    return _find_token_value(payload)


def _find_token_value(payload: Any) -> str | None:
    if isinstance(payload, str):
        return payload.strip() or None

    if isinstance(payload, dict):
        for key in ("token", "access_token", "jwt", "jwt_token"):
            value = payload.get(key)
            token = _find_token_value(value)
            if token is not None:
                return token

        for key in ("data", "result", "payload"):
            nested_payload = payload.get(key)
            token = _find_token_value(nested_payload)
            if token is not None:
                return token

    return None


def _decode_json_payload(body: bytes, *, charset: str | None) -> Any | None:
    if not body:
        return None

    encoding = charset or "utf-8"
    try:
        return json.loads(body.decode(encoding))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _decode_text_payload(body: bytes, *, charset: str | None) -> str:
    if not body:
        return ""

    encoding = charset or "utf-8"
    try:
        return body.decode(encoding).strip()
    except UnicodeDecodeError:
        return body.decode("utf-8", errors="replace").strip()


def _extract_jwt_expiration(token_value: str) -> float | None:
    parts = token_value.split(".")
    if len(parts) < 2:
        return None

    payload_segment = parts[1]
    padded_segment = payload_segment + "=" * (-len(payload_segment) % 4)

    try:
        payload_json = base64.urlsafe_b64decode(padded_segment.encode("ascii")).decode("utf-8")
        payload = json.loads(payload_json)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None

    exp = payload.get("exp")
    if isinstance(exp, (int, float)) and exp > 0:
        return float(exp)

    return None
