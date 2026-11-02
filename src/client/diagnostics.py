"""Allowlisted diagnostic metadata; never serialize request/response bodies."""
from __future__ import annotations

from contextvars import ContextVar
import json
import re
from typing import Any
from uuid import UUID


trace_id: ContextVar[str] = ContextVar("diagnostic_trace_id", default="-")

# Free-form server messages can echo a password, subject, document or token.
# Only these complete, static messages may be written verbatim.
_SAFE_MESSAGES = frozenset({
    "Идентификатор процесса GUID уже существует",
    "Идентификатор процесса GUID не найден",
    "Передан недействительный OID политики применения сертификатов",
    "Файл не найден", "Файл не существует", "Диск не найден",
    "Операция отменена", "Ввод пароля отменен",
    "Пароль ключа неверный или файл ключа поврежден",
    "Ошибка при чтении PFX-файла",
    "E-IMZO response timeout", "Remote API request failed.",
})
_SAFE_CODES = frozenset({
    "CLIENT_ERROR", "ACCESS_SERVICE_UNAVAILABLE", "ACCESS_CHECK_FAILED",
    "ORIGIN_ACCESS_DENIED", "ORIGIN_REQUIRED", "ORIGIN_INVALID",
    "ROLE_REQUIRED", "AUDIT_METADATA_REQUIRED",
})
_CLASS_NAME = re.compile(r"(?:java|javax|uz|org|io)\.[\w.$]+(?:Exception|Error)")


def enrollment_guid(command: Any) -> str | None:
    if command.plugin != "pki" or command.name not in {"enroll_pfx_step1", "enroll_pfx_step2"}:
        return None
    arguments = command.arguments
    if isinstance(arguments, dict):
        arguments = arguments.get("arguments")
    return _guid(arguments[0]) if isinstance(arguments, (list, tuple)) and arguments else None


def _guid(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) != 36:
        return None
    try:
        return str(UUID(value))
    except ValueError:
        return None


def response_summary(body: bytes, charset: str | None = None) -> str:
    """Return bounded JSON containing only explicitly permitted fields."""
    result: dict[str, Any] = {"response_bytes": len(body)}
    try:
        payload = json.loads(body.decode(charset or "utf-8"))
    except (LookupError, UnicodeError, ValueError, RecursionError):
        result["response_format"] = "empty" if not body else "non_json"
        return json.dumps(result)
    result["response_format"] = "json"
    if not isinstance(payload, dict):
        result["json_type"] = type(payload).__name__
        if isinstance(payload, list):
            result["items"] = len(payload)
        return json.dumps(result)
    if type(payload.get("success")) is bool:
        result["success"] = payload["success"]
    if type(payload.get("status")) is int:
        result["status"] = payload["status"]
    guid = _guid(payload.get("guid"))
    if guid:
        result["guid"] = guid
    for name in ("reason", "message", "error"):
        value = payload.get(name)
        if isinstance(value, str):
            result[name] = value if value in _SAFE_MESSAGES else "[omitted]"
            result[name + "_chars"] = len(value)
    if isinstance(payload.get("code"), str) and payload["code"] in _SAFE_CODES:
        result["code"] = payload["code"]
    class_name = payload.get("className")
    if isinstance(class_name, str) and len(class_name) <= 180 and _CLASS_NAME.fullmatch(class_name):
        result["className"] = class_name
    frames = []
    stack = payload.get("stackTrace")
    if isinstance(stack, list):
        for frame in stack[:8]:
            if not isinstance(frame, dict):
                continue
            owner = frame.get("className", frame.get("declaringClass"))
            method = frame.get("methodName")
            line = frame.get("lineNumber")
            if (isinstance(owner, str) and len(owner) <= 180
                    and re.fullmatch(r"(?:java|javax|uz|org|io)\.[\w.$]+", owner)
                    and isinstance(method, str) and re.fullmatch(r"[\w$<>]{1,80}", method)
                    and type(line) is int):
                frames.append(f"{owner}.{method}:{line}")
    if frames:
        result["frames"] = frames
    # Lengths reveal missing/truncated crypto fields without recording their contents.
    for name in ("pkcs10_64", "pkcs7_64"):
        if name in payload:
            value = payload[name]
            result[name + "_chars"] = len(value) if isinstance(value, str) else None
    for name in ("password", "alias", "disk"):
        if name in payload:
            result[name + "_present"] = isinstance(payload[name], str) and bool(payload[name])
    return json.dumps(result, ensure_ascii=False, separators=(",", ":"))
