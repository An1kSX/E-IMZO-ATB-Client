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
from client.domain.key_identity_store import KeyIdentity, KeyIdentityStore
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
_APPEND_PKCS7_ATTACHED_COMMAND_NAME = "append_pkcs7_attached"
_VERIFY_PASSWORD_COMMAND_NAME = "verify_password"
_CHANGE_PASSWORD_COMMAND_NAME = "change_password"
_AUTH_PLUGIN_NAME = "auth"
_AUTH_LOGIN_COMMAND_NAME = "login"
_AUTH_INVALID_STATUS_CODES = {400, 401, 403}
_ACCESS_TOKEN_REFRESH_LEEWAY_SECONDS = 30.0
_SENSITIVE_CONFIRMATION_COOLDOWN_SECONDS = 3.0
_MISSING = object()
_IDENTITY_ARGUMENT_KEY_ID_INDEXES: dict[tuple[str | None, str], int] = {
    (_PKCS7_PLUGIN_NAME, _CREATE_PKCS7_COMMAND_NAME): 1,
    (_PKCS7_PLUGIN_NAME, _APPEND_PKCS7_ATTACHED_COMMAND_NAME): 1,
    (_PFX_PLUGIN_NAME, _VERIFY_PASSWORD_COMMAND_NAME): 0,
    (_PFX_PLUGIN_NAME, _CHANGE_PASSWORD_COMMAND_NAME): 0,
}
_SENSITIVE_CONFIRMATION_COOLDOWN_COMMANDS: set[tuple[str | None, str]] = {
    (_PKCS7_PLUGIN_NAME, _CREATE_PKCS7_COMMAND_NAME),
    (_PKCS7_PLUGIN_NAME, _APPEND_PKCS7_ATTACHED_COMMAND_NAME),
    (_PFX_PLUGIN_NAME, _VERIFY_PASSWORD_COMMAND_NAME),
}
_SENSITIVE_CONFIRMATION_COOLDOWN_GROUP_PASSWORD_AUTOFILL = "password_autofill"
LOGGER = logging.getLogger(__name__)
_USER_ACTION_LOG_EXTRA = {"user_action": True}


class _UpstreamRequestError(RuntimeError):
    """Raised when an HTTP request to E-IMZO API cannot be completed."""


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
    error_message: str | None = None


@dataclass(frozen=True, slots=True)
class AccessToken:
    value: str
    expires_at: float | None

    def is_valid(self, *, now: float) -> bool:
        if self.expires_at is None:
            return True
        return (now + _ACCESS_TOKEN_REFRESH_LEEWAY_SECONDS) < self.expires_at


@dataclass(frozen=True, slots=True)
class _LoadKeyIdentityPayload:
    key_alias: str | None
    key_subject: str | None


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
        self._sensitive_confirmation_cooldown_until_by_key: dict[tuple[str | None, str, str], float] = {}
        self._sensitive_confirmation_locks_by_key: dict[tuple[str | None, str, str], asyncio.Lock] = {}

    async def ensure_authenticated(self) -> bool:
        try:
            token = await self._ensure_access_token(
                reason="Введите пароль для входа в E-IMZO перед началом работы приложения.",
            )
            return token is not None
        except _UpstreamRequestError as error:
            LOGGER.warning("Could not authenticate with E-IMZO API during startup: %s", error)
            return False

    async def forward(self, command: ProxyCommand, *, origin: str | None = None) -> ProxyResponse:
        endpoint_url = self._build_endpoint_url(command.plugin, command.name)
        load_key_identity_payload = _extract_identity_payload_from_load_key_command(command)
        prepared_request = self._build_request(command, origin=origin)
        command_label = _format_command_label(plugin=command.plugin, name=command.name)

        if prepared_request.error_message is not None:
            LOGGER.warning(
                "Rejected %s before forwarding because the key identity is missing.",
                command_label,
            )
            return _failed_proxy_response(prepared_request.error_message)

        if prepared_request.sensitive_identity is not None:
            cooldown_key = self._build_sensitive_confirmation_cooldown_key(
                command=command,
                origin=origin,
                identity=prepared_request.sensitive_identity,
            )

            if cooldown_key is not None:
                confirmation_lock = self._sensitive_confirmation_locks_by_key.setdefault(cooldown_key, asyncio.Lock())
                async with confirmation_lock:
                    if self._is_sensitive_confirmation_cooldown_active(cooldown_key):
                        LOGGER.info(
                            "Skipped confirmation for %s due cooldown. origin=%s identity=%s",
                            command_label,
                            origin,
                            prepared_request.sensitive_identity,
                            extra=_USER_ACTION_LOG_EXTRA,
                        )
                        approved = True
                    else:
                        approved = await self._prompt_service.confirm_sensitive_operation(
                            command=command,
                            identity=prepared_request.sensitive_identity,
                        )
                        if approved:
                            self._remember_sensitive_confirmation(cooldown_key)
            else:
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

        try:
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

            self._remember_key_identity(
                load_key_identity_payload=load_key_identity_payload,
                response=response.proxy_response,
                origin=origin,
            )
            return response.proxy_response
        except _UpstreamRequestError as error:
            LOGGER.warning("E-IMZO API request failed for %s: %s", command_label, error)
            return _failed_proxy_response(str(error))

    def _build_endpoint_url(self, plugin: str | None, name: str) -> str:
        segments = [self._api_base_url]
        if self._api_path_prefix:
            segments.append(self._api_path_prefix.strip("/"))
        if plugin:
            segments.append(str(plugin).strip("/"))
        segments.append(str(name).strip("/"))
        return "/".join(segment for segment in segments if segment)

    def get_identity_by_key_id(self, key_id: str, *, origin: str | None = None) -> str | None:
        identity = self._key_identity_store.get_key_identity(key_id, origin=origin)
        if identity is None:
            return None
        return identity.first_available()

    def _remember_key_identity(
        self,
        *,
        load_key_identity_payload: _LoadKeyIdentityPayload | None,
        response: ProxyResponse,
        origin: str | None,
    ) -> None:
        if load_key_identity_payload is None:
            return

        key_id = _extract_key_id_from_response(response.body, charset=response.charset)
        if key_id is None:
            return

        identity = self._key_identity_store.remember(
            key_id=key_id,
            key_alias=load_key_identity_payload.key_alias,
            key_subject=load_key_identity_payload.key_subject,
            origin=origin,
        )
        if identity is None:
            LOGGER.warning(
                "Could not extract INN/PINFL from load_key payload for keyId %s (alias=%r subject=%r)",
                key_id,
                load_key_identity_payload.key_alias,
                load_key_identity_payload.key_subject,
            )
            return

        LOGGER.info(
            "Stored keyId identities: origin=%s keyId=%s inn=%s pinfl=%s",
            origin,
            key_id,
            identity.inn,
            identity.pinfl,
        )

    def _build_request(self, command: ProxyCommand, *, origin: str | None = None) -> PreparedRequest:
        arguments = command.arguments
        if not command.has_arguments:
            return PreparedRequest(arguments=arguments)

        if not isinstance(arguments, (list, tuple)):
            return PreparedRequest(arguments=arguments)

        key_id = _extract_key_id_from_identity_command(command=command, arguments=arguments)
        if key_id is None:
            return PreparedRequest(arguments=arguments)

        command_label = _format_command_label(plugin=command.plugin, name=command.name)
        identity = self._key_identity_store.get_key_identity(key_id, origin=origin)
        if identity is None:
            LOGGER.warning("No stored INN/PINFL found for origin=%s keyId=%s during %s", origin, key_id, command_label)
            return PreparedRequest(
                arguments=arguments,
                error_message=(
                    "Не удалось определить ИНН/ПИНФЛ для выбранного ключа. "
                    "Загрузите ключ заново и повторите операцию."
                ),
            )

        identity_values = identity.argument_values()
        if not identity_values:
            LOGGER.warning("Stored identity for origin=%s keyId=%s is empty during %s", origin, key_id, command_label)
            return PreparedRequest(
                arguments=arguments,
                error_message=(
                    "РќРµ СѓРґР°Р»РѕСЃСЊ РѕРїСЂРµРґРµР»РёС‚СЊ РРќРќ/РџРРќР¤Р› РґР»СЏ РІС‹Р±СЂР°РЅРЅРѕРіРѕ РєР»СЋС‡Р°. "
                    "Р—Р°РіСЂСѓР·РёС‚Рµ РєР»СЋС‡ Р·Р°РЅРѕРІРѕ Рё РїРѕРІС‚РѕСЂРёС‚Рµ РѕРїРµСЂР°С†РёСЋ."
                ),
            )

        request_arguments = list(arguments)
        _remove_reverse_identity_suffix(arguments=request_arguments, identity_values=identity_values)
        if not _arguments_end_with_identity_values(arguments=request_arguments, identity_values=identity_values):
            request_arguments.extend(identity_values)
            LOGGER.info(
                "Added identity arguments %s to %s arguments for keyId %s",
                identity_values,
                command_label,
                key_id,
            )

        return PreparedRequest(
            arguments=request_arguments,
            sensitive_identity=_format_identity_for_prompt(identity),
        )

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
        try:
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
        except (aiohttp.ClientError, asyncio.TimeoutError) as error:
            raise _UpstreamRequestError(
                _format_transport_error_message(
                    method=method,
                    endpoint_url=endpoint_url,
                    error=error,
                )
            ) from error

    def _build_sensitive_confirmation_cooldown_key(
        self,
        *,
        command: ProxyCommand,
        origin: str | None,
        identity: str,
    ) -> tuple[str | None, str, str] | None:
        if (command.plugin, command.name) not in _SENSITIVE_CONFIRMATION_COOLDOWN_COMMANDS:
            return None
        return (
            _normalize_origin(origin),
            identity,
            _SENSITIVE_CONFIRMATION_COOLDOWN_GROUP_PASSWORD_AUTOFILL,
        )

    def _is_sensitive_confirmation_cooldown_active(self, cooldown_key: tuple[str | None, str, str]) -> bool:
        expires_at = self._sensitive_confirmation_cooldown_until_by_key.get(cooldown_key)
        if expires_at is None:
            return False
        return expires_at > self._clock()

    def _remember_sensitive_confirmation(self, cooldown_key: tuple[str | None, str, str]) -> None:
        self._sensitive_confirmation_cooldown_until_by_key[cooldown_key] = (
            self._clock() + _SENSITIVE_CONFIRMATION_COOLDOWN_SECONDS
        )


def _cancelled_proxy_response() -> ProxyResponse:
    return ProxyResponse.from_json({"success": False})


def _failed_proxy_response(message: str) -> ProxyResponse:
    return ProxyResponse.from_json({"success": False, "message": message})


def _format_transport_error_message(*, method: str, endpoint_url: str, error: Exception) -> str:
    if isinstance(error, asyncio.TimeoutError):
        details = "Request timed out."
    else:
        details = str(error).strip() or error.__class__.__name__
    return f"{method} {endpoint_url}: {details}"


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


def _extract_identity_payload_from_load_key_command(command: ProxyCommand) -> _LoadKeyIdentityPayload | None:
    if command.plugin != _PFX_PLUGIN_NAME or command.name != _LOAD_KEY_COMMAND_NAME:
        return None

    key_alias: str | None = None
    key_subject: str | None = None
    arguments = command.arguments
    if isinstance(arguments, dict):
        key_alias = _extract_first_non_empty_mapping_value(
            arguments,
            keys=("key_alias", "keyAlias", "key_name", "keyName", "name", "alias"),
        )
        key_subject = _extract_first_non_empty_mapping_value(
            arguments,
            keys=("subject", "subjectName", "subject_name", "certificate_subject", "cert_subject", "dn"),
        )
        if key_subject is None:
            key_subject = _build_subject_from_identity_mapping(arguments)
    elif isinstance(arguments, (list, tuple)):
        if len(arguments) >= 3 and isinstance(arguments[2], str) and arguments[2].strip():
            key_alias = arguments[2].strip()
        if len(arguments) >= 4 and isinstance(arguments[3], str) and arguments[3].strip():
            key_subject = arguments[3].strip()

    if key_alias is None and key_subject is None:
        return None
    return _LoadKeyIdentityPayload(key_alias=key_alias, key_subject=key_subject)


def _extract_first_non_empty_mapping_value(mapping: dict[str, Any], *, keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _build_subject_from_identity_mapping(mapping: dict[str, Any]) -> str | None:
    extracted_parts: list[str] = []
    for key in ("uid", "1.2.860.3.16.1.1", "1.2.860.3.16.1.2"):
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            extracted_parts.append(f"{key}={value.strip()}")
    if not extracted_parts:
        return None
    return ",".join(extracted_parts)


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


def _normalize_origin(origin: str | None) -> str | None:
    if origin is None:
        return None

    normalized_origin = origin.strip().casefold()
    if not normalized_origin:
        return None
    return normalized_origin


def _arguments_end_with_identity_values(*, arguments: list[Any], identity_values: list[str]) -> bool:
    if not identity_values:
        return True
    if len(arguments) < len(identity_values):
        return False
    return arguments[-len(identity_values) :] == identity_values


def _remove_reverse_identity_suffix(*, arguments: list[Any], identity_values: list[str]) -> None:
    if len(identity_values) != 2:
        return
    if len(arguments) < 2:
        return

    reverse_values = [identity_values[1], identity_values[0]]
    if reverse_values == identity_values:
        return

    if arguments[-2:] == reverse_values:
        del arguments[-2:]


def _format_identity_for_prompt(identity: KeyIdentity) -> str | None:
    if identity.inn and identity.pinfl:
        return f"ИНН {identity.inn}, ПИНФЛ {identity.pinfl}"
    if identity.inn:
        return f"ИНН {identity.inn}"
    if identity.pinfl:
        return f"ПИНФЛ {identity.pinfl}"
    return None


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

