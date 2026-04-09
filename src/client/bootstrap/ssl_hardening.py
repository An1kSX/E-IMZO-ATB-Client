from __future__ import annotations

import logging
import os
import platform
import ssl
from os import PathLike

try:
    import certifi
except ImportError:
    certifi = None

LOGGER = logging.getLogger(__name__)
_ORIGINAL_CREATE_DEFAULT_CONTEXT = ssl.create_default_context
_DISABLE_CERT_STORE_FALLBACK_ENV = "EIMZO_DISABLE_SSL_CERT_STORE_FALLBACK"
_FORCE_CERTIFI_BUNDLE_ENV = "EIMZO_FORCE_CERTIFI_BUNDLE"
_WINDOWS_CERT_STORE_ERROR_TOKENS = (
    "nested asn1 error",
    "asn1",
    "windows store",
)
_PATCH_INSTALLED = False


def install_ssl_cert_store_fallback() -> None:
    global _PATCH_INSTALLED

    if _PATCH_INSTALLED:
        return
    _PATCH_INSTALLED = True

    if _is_env_enabled(_DISABLE_CERT_STORE_FALLBACK_ENV):
        LOGGER.info(
            "Windows certificate-store fallback is disabled by %s.",
            _DISABLE_CERT_STORE_FALLBACK_ENV,
        )
        return

    ssl.create_default_context = create_default_context_with_windows_store_fallback
    if hasattr(ssl, "_create_default_https_context"):
        ssl._create_default_https_context = create_default_context_with_windows_store_fallback


def create_default_context_with_windows_store_fallback(
    purpose: ssl.Purpose = ssl.Purpose.SERVER_AUTH,
    *,
    cafile: str | PathLike[str] | None = None,
    capath: str | PathLike[str] | None = None,
    cadata: str | bytes | None = None,
) -> ssl.SSLContext:
    force_certifi_bundle = _is_env_enabled(_FORCE_CERTIFI_BUNDLE_ENV)
    if force_certifi_bundle and cafile is None and capath is None and cadata is None:
        certifi_bundle = _resolve_certifi_bundle_path()
        if certifi_bundle:
            return _ORIGINAL_CREATE_DEFAULT_CONTEXT(
                purpose=purpose,
                cafile=certifi_bundle,
                capath=None,
                cadata=None,
            )

    try:
        return _ORIGINAL_CREATE_DEFAULT_CONTEXT(
            purpose=purpose,
            cafile=cafile,
            capath=capath,
            cadata=cadata,
        )
    except ssl.SSLError as error:
        if cafile is not None or capath is not None or cadata is not None:
            raise
        if not is_windows_certificate_store_ssl_error(error):
            raise

        certifi_bundle = _resolve_certifi_bundle_path()
        if certifi_bundle is None:
            raise

        LOGGER.warning(
            "Windows certificate store is unavailable. Falling back to certifi bundle: %s",
            certifi_bundle,
        )
        return _ORIGINAL_CREATE_DEFAULT_CONTEXT(
            purpose=purpose,
            cafile=certifi_bundle,
            capath=None,
            cadata=None,
        )


def load_default_certs_safely(
    context: ssl.SSLContext,
    purpose: ssl.Purpose = ssl.Purpose.SERVER_AUTH,
) -> bool:
    try:
        context.load_default_certs(purpose)
        return True
    except ssl.SSLError as error:
        if not is_windows_certificate_store_ssl_error(error):
            raise

        LOGGER.warning(
            "Could not load default Windows trust store certificates. "
            "Continuing without Windows store roots."
        )
        return False


def is_windows_certificate_store_ssl_error(error: BaseException) -> bool:
    if platform.system() != "Windows":
        return False

    for candidate in _walk_exception_chain(error):
        if not isinstance(candidate, ssl.SSLError):
            continue
        normalized = str(candidate).casefold()
        if any(token in normalized for token in _WINDOWS_CERT_STORE_ERROR_TOKENS):
            return True

    return False


def _resolve_certifi_bundle_path() -> str | None:
    if certifi is None:
        return None

    try:
        bundle_path = certifi.where()
    except Exception as error:  # pragma: no cover - defensive logging
        LOGGER.warning("Could not resolve certifi bundle path: %s", error)
        return None

    if not bundle_path:
        return None

    return str(bundle_path)


def _is_env_enabled(name: str) -> bool:
    value = os.getenv(name)
    if value is None:
        return False
    return value.strip().casefold() in {"1", "true", "yes", "on"}


def _walk_exception_chain(error: BaseException) -> list[BaseException]:
    chain: list[BaseException] = []
    visited: set[int] = set()
    current: BaseException | None = error
    while current is not None:
        current_id = id(current)
        if current_id in visited:
            break
        visited.add(current_id)
        chain.append(current)
        next_error = current.__cause__
        if next_error is None:
            next_error = current.__context__
        current = next_error
    return chain
