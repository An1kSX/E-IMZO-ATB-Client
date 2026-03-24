from __future__ import annotations

import ctypes
from ctypes import wintypes
import getpass
import platform

_NAME_SAM_COMPATIBLE = 2


def resolve_account_name(override: str | None = None) -> str:
    if override:
        return override

    if platform.system() != "Windows":
        return getpass.getuser()

    try:
        account = _resolve_windows_account_name()
        account = account.split("\\")[-1]  # Remove domain if present
        return account
    except Exception:
        return getpass.getuser()


def _resolve_windows_account_name() -> str:
    size = wintypes.ULONG(0)
    secur32 = ctypes.windll.secur32

    secur32.GetUserNameExW(_NAME_SAM_COMPATIBLE, None, ctypes.byref(size))
    if size.value <= 1:
        raise RuntimeError("Unable to determine current Windows account name.")

    buffer = ctypes.create_unicode_buffer(size.value)
    if not secur32.GetUserNameExW(_NAME_SAM_COMPATIBLE, buffer, ctypes.byref(size)):
        raise ctypes.WinError()

    return buffer.value
