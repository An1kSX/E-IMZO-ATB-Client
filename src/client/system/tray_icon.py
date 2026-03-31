from __future__ import annotations

import ctypes
from ctypes import wintypes
import logging
from pathlib import Path
import sys
import threading
from typing import Callable

LOGGER = logging.getLogger(__name__)
_USER_ACTION_LOG_EXTRA = {"user_action": True}

_WM_CLOSE = 0x0010
_WM_DESTROY = 0x0002
_WM_NULL = 0x0000
_WM_RBUTTONDOWN = 0x0204
_WM_RBUTTONUP = 0x0205
_WM_CONTEXTMENU = 0x007B
_WM_APP = 0x8000
_WM_TRAYICON = _WM_APP + 1

_NIM_ADD = 0x00000000
_NIM_DELETE = 0x00000002
_NIM_SETFOCUS = 0x00000003
_NIM_SETVERSION = 0x00000004
_NIF_MESSAGE = 0x00000001
_NIF_ICON = 0x00000002
_NIF_TIP = 0x00000004
_NOTIFYICON_VERSION_4 = 4

_MF_STRING = 0x00000000
_TPM_LEFTALIGN = 0x0000
_TPM_BOTTOMALIGN = 0x0020
_TPM_RIGHTBUTTON = 0x0002
_TPM_RETURNCMD = 0x0100

_IDI_APPLICATION = 32512
_EXIT_MENU_ITEM_ID = 1001
_TOOLTIP_TEXT = "E-IMZO ATB Client"
_WINDOW_CLASS_NAME = "EimzoAtbClientTrayWindow"
_IMAGE_ICON = 1
_LR_LOADFROMFILE = 0x00000010
_LR_DEFAULTSIZE = 0x00000040

_user32 = ctypes.windll.user32
_kernel32 = ctypes.windll.kernel32
_shell32 = ctypes.windll.shell32
_LRESULT = ctypes.c_ssize_t


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class _POINT(ctypes.Structure):
    _fields_ = [
        ("x", wintypes.LONG),
        ("y", wintypes.LONG),
    ]


class _MSG(ctypes.Structure):
    _fields_ = [
        ("hwnd", wintypes.HWND),
        ("message", wintypes.UINT),
        ("wParam", wintypes.WPARAM),
        ("lParam", wintypes.LPARAM),
        ("time", wintypes.DWORD),
        ("pt", _POINT),
        ("lPrivate", wintypes.DWORD),
    ]


class _WNDCLASSW(ctypes.Structure):
    _fields_ = [
        ("style", wintypes.UINT),
        ("lpfnWndProc", ctypes.c_void_p),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wintypes.HINSTANCE),
        ("hIcon", wintypes.HANDLE),
        ("hCursor", wintypes.HANDLE),
        ("hbrBackground", wintypes.HANDLE),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
    ]


class _NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("hWnd", wintypes.HWND),
        ("uID", wintypes.UINT),
        ("uFlags", wintypes.UINT),
        ("uCallbackMessage", wintypes.UINT),
        ("hIcon", wintypes.HANDLE),
        ("szTip", wintypes.WCHAR * 128),
        ("dwState", wintypes.DWORD),
        ("dwStateMask", wintypes.DWORD),
        ("szInfo", wintypes.WCHAR * 256),
        ("uVersion", wintypes.UINT),
        ("szInfoTitle", wintypes.WCHAR * 64),
        ("dwInfoFlags", wintypes.DWORD),
        ("guidItem", _GUID),
        ("hBalloonIcon", wintypes.HANDLE),
    ]


_WNDPROC = ctypes.WINFUNCTYPE(
    _LRESULT,
    wintypes.HWND,
    wintypes.UINT,
    wintypes.WPARAM,
    wintypes.LPARAM,
)


class WindowsTrayIcon:
    def __init__(
        self,
        *,
        on_exit_request: Callable[[], None],
        icon_path: Path | None = None,
    ) -> None:
        self._on_exit_request = on_exit_request
        self._icon_path = icon_path
        self._thread: threading.Thread | None = None
        self._thread_id: int | None = None
        self._hwnd: int | None = None
        self._window_proc = _WNDPROC(self._wnd_proc)
        self._ready_event = threading.Event()
        self._startup_error: BaseException | None = None
        self._icon_added = False
        self._icon_handle: int | None = None
        self._owns_icon_handle = False
        self._shutdown_requested = False

    def start(self) -> None:
        if self._thread is not None:
            return

        self._thread = threading.Thread(
            target=self._run_message_loop,
            name="eimzo-tray-icon",
            daemon=True,
        )
        self._thread.start()
        self._ready_event.wait(timeout=5.0)
        if self._startup_error is not None:
            raise RuntimeError("Failed to start Windows tray icon.") from self._startup_error

    def stop(self) -> None:
        if self._thread is None:
            return

        hwnd = self._hwnd
        if hwnd:
            _user32.PostMessageW(hwnd, _WM_CLOSE, 0, 0)
        elif self._thread_id is not None:
            _user32.PostThreadMessageW(self._thread_id, 0x0012, 0, 0)

        self._thread.join(timeout=5.0)
        self._thread = None

    def _run_message_loop(self) -> None:
        try:
            self._thread_id = _kernel32.GetCurrentThreadId()
            self._hwnd = self._create_hidden_window()
            self._add_tray_icon()
        except BaseException as error:  # noqa: BLE001
            self._startup_error = error
            self._ready_event.set()
            return

        self._ready_event.set()

        message = _MSG()
        while _user32.GetMessageW(ctypes.byref(message), None, 0, 0) > 0:
            _user32.TranslateMessage(ctypes.byref(message))
            _user32.DispatchMessageW(ctypes.byref(message))

        self._remove_tray_icon()
        self._release_icon()
        self._hwnd = None

    def _create_hidden_window(self) -> int:
        hinstance = _kernel32.GetModuleHandleW(None)

        window_class = _WNDCLASSW()
        window_class.lpfnWndProc = ctypes.cast(self._window_proc, ctypes.c_void_p).value
        window_class.hInstance = hinstance
        window_class.lpszClassName = _WINDOW_CLASS_NAME
        atom = _user32.RegisterClassW(ctypes.byref(window_class))
        if atom == 0:
            error_code = ctypes.get_last_error()
            if error_code != 1410:
                raise ctypes.WinError(error_code)

        hwnd = _user32.CreateWindowExW(
            0,
            _WINDOW_CLASS_NAME,
            _WINDOW_CLASS_NAME,
            0,
            0,
            0,
            0,
            0,
            None,
            None,
            hinstance,
            None,
        )
        if hwnd == 0:
            raise ctypes.WinError(ctypes.get_last_error())

        return hwnd

    def _add_tray_icon(self) -> None:
        if self._hwnd is None:
            return

        notify_data = self._build_notify_data(self._hwnd)
        if not _shell32.Shell_NotifyIconW(_NIM_ADD, ctypes.byref(notify_data)):
            raise ctypes.WinError(ctypes.get_last_error())

        notify_data.uVersion = _NOTIFYICON_VERSION_4
        _shell32.Shell_NotifyIconW(_NIM_SETVERSION, ctypes.byref(notify_data))
        self._icon_added = True

    def _remove_tray_icon(self) -> None:
        if not self._icon_added or self._hwnd is None:
            return

        notify_data = self._build_notify_data(self._hwnd)
        _shell32.Shell_NotifyIconW(_NIM_DELETE, ctypes.byref(notify_data))
        self._icon_added = False

    def _build_notify_data(self, hwnd: int) -> _NOTIFYICONDATAW:
        notify_data = _NOTIFYICONDATAW()
        notify_data.cbSize = ctypes.sizeof(_NOTIFYICONDATAW)
        notify_data.hWnd = hwnd
        notify_data.uID = 1
        notify_data.uFlags = _NIF_MESSAGE | _NIF_ICON | _NIF_TIP
        notify_data.uCallbackMessage = _WM_TRAYICON
        notify_data.hIcon = self._resolve_icon_handle()
        notify_data.szTip = _TOOLTIP_TEXT
        return notify_data

    def _resolve_icon_handle(self) -> int:
        if self._icon_handle:
            return self._icon_handle

        if self._icon_path is not None:
            loaded_icon = _user32.LoadImageW(
                None,
                str(self._icon_path),
                _IMAGE_ICON,
                0,
                0,
                _LR_LOADFROMFILE | _LR_DEFAULTSIZE,
            )
            if loaded_icon:
                self._icon_handle = int(loaded_icon)
                self._owns_icon_handle = True
                return self._icon_handle
            LOGGER.warning("Could not load tray icon from %s", self._icon_path)

        if getattr(sys, "frozen", False):
            extracted_icon = _shell32.ExtractIconW(None, str(Path(sys.executable)), 0)
            if extracted_icon and int(extracted_icon) > 1:
                self._icon_handle = int(extracted_icon)
                self._owns_icon_handle = True
                return self._icon_handle

        self._icon_handle = int(_user32.LoadIconW(None, _make_int_resource(_IDI_APPLICATION)))
        self._owns_icon_handle = False
        return self._icon_handle

    def _release_icon(self) -> None:
        if self._icon_handle and self._owns_icon_handle:
            _user32.DestroyIcon(self._icon_handle)
        self._icon_handle = None
        self._owns_icon_handle = False

    def _request_shutdown(self, hwnd: int, *, reason: str) -> None:
        if self._shutdown_requested:
            return

        self._shutdown_requested = True
        LOGGER.info("Shutdown requested from tray icon: %s", reason, extra=_USER_ACTION_LOG_EXTRA)
        self._on_exit_request()
        if hwnd:
            _user32.DestroyWindow(hwnd)

    def _wnd_proc(
        self,
        hwnd: int,
        message: int,
        w_param: int,
        l_param: int,
    ) -> int:
        if message == _WM_TRAYICON:
            event_code, anchor = _resolve_tray_event(w_param, l_param)
            LOGGER.debug(
                "Tray callback received: event=%#x wParam=%#x lParam=%#x anchor=%s",
                event_code,
                w_param,
                l_param,
                None if anchor is None else f"({anchor.x}, {anchor.y})",
            )
            if event_code in {_WM_RBUTTONDOWN, _WM_RBUTTONUP, _WM_CONTEXTMENU}:
                self._request_shutdown(hwnd, reason=f"tray-event:{event_code:#x}")
                return 0

        if message == _WM_CONTEXTMENU:
            LOGGER.debug(
                "Window context-menu message received directly: hwnd=%s wParam=%#x lParam=%#x",
                hwnd,
                w_param,
                l_param,
            )
            self._request_shutdown(hwnd, reason="window-context-menu")
            return 0

        if message == _WM_DESTROY:
            self._remove_tray_icon()
            _user32.PostQuitMessage(0)
            return 0

        return _user32.DefWindowProcW(hwnd, message, w_param, l_param)


def _make_int_resource(value: int) -> wintypes.LPCWSTR:
    return ctypes.cast(ctypes.c_void_p(value & 0xFFFF), wintypes.LPCWSTR)


def _low_word(value: int) -> int:
    return value & 0xFFFF


def _high_word(value: int) -> int:
    return (value >> 16) & 0xFFFF


def _signed_word(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


def _notification_anchor_point(w_param: int) -> _POINT:
    return _POINT(
        x=_signed_word(_low_word(w_param)),
        y=_signed_word(_high_word(w_param)),
    )


def _resolve_tray_event(w_param: int, l_param: int) -> tuple[int, _POINT | None]:
    if _high_word(l_param):
        return _low_word(l_param), _notification_anchor_point(w_param)
    return int(l_param), None
