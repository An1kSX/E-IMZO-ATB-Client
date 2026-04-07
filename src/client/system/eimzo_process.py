from __future__ import annotations

from dataclasses import dataclass
import csv
import logging
import os
import platform
import subprocess
import json

LOGGER = logging.getLogger(__name__)
_EIMZO_PROCESS_NAME = "E-IMZO.exe"
_EIMZO_INSTALL_DIR = r"c:\program files (x86)\e-imzo"
_EIMZO_PROCESS_NAME_ALIASES = {
    _EIMZO_PROCESS_NAME.casefold(),
    "javaw.exe",
    "java.exe",
}


@dataclass(frozen=True, slots=True)
class ListeningProcess:
    pid: int
    name: str
    executable_path: str | None = None
    command_line: str | None = None


@dataclass(frozen=True, slots=True)
class WindowsProcessInfo:
    pid: int
    name: str
    executable_path: str | None = None
    command_line: str | None = None


def is_port_in_use(*, port: int) -> bool:
    if platform.system() != "Windows":
        return False

    return _resolve_windows_pid_by_port(port=port) is not None


def find_listening_process_by_port(*, port: int) -> ListeningProcess | None:
    if platform.system() != "Windows":
        return None

    pid = _resolve_windows_pid_by_port(port=port)
    if pid is None:
        return None

    process_snapshot = _resolve_windows_process_snapshot()
    for process in process_snapshot:
        if process.pid != pid:
            continue
        return ListeningProcess(
            pid=process.pid,
            name=process.name,
            executable_path=process.executable_path,
            command_line=process.command_line,
        )

    name = _resolve_windows_process_name(pid=pid)
    if name is None:
        return None

    return ListeningProcess(pid=pid, name=name)


def terminate_process_by_pid(*, pid: int) -> bool:
    if platform.system() != "Windows" or pid <= 0:
        return False

    if _stop_process_via_powershell(pid=pid):
        return True

    completed = subprocess.run(
        ["taskkill", "/PID", str(pid), "/T", "/F"],
        check=False,
        capture_output=True,
        text=True,
        creationflags=_windows_creation_flags(),
    )
    if completed.returncode == 0:
        return True

    LOGGER.warning(
        "Could not terminate PID %s via taskkill. returncode=%s stderr=%s",
        pid,
        completed.returncode,
        (completed.stderr or "").strip(),
    )
    return False


def terminate_related_eimzo_processes(*, listening_process: ListeningProcess) -> bool:
    if platform.system() != "Windows":
        return False

    process_snapshot = _resolve_windows_process_snapshot()
    target_pids = [
        process.pid
        for process in process_snapshot
        if is_eimzo_process(process)
    ]
    if not target_pids:
        target_pids = [listening_process.pid]

    terminated_any = False
    current_pid = os.getpid()
    for pid in target_pids:
        if pid <= 0 or pid == current_pid:
            continue
        if terminate_process_by_pid(pid=pid):
            terminated_any = True

    return terminated_any


def is_eimzo_process_name(name: str) -> bool:
    return name.strip().casefold() in _EIMZO_PROCESS_NAME_ALIASES


def is_eimzo_process(process: ListeningProcess | WindowsProcessInfo) -> bool:
    return _matches_eimzo_identity(
        name=process.name,
        executable_path=process.executable_path,
        command_line=process.command_line,
    )


def _resolve_windows_pid_by_port(*, port: int) -> int | None:
    completed = subprocess.run(
        ["netstat", "-ano", "-p", "tcp"],
        check=False,
        capture_output=True,
        text=True,
        creationflags=_windows_creation_flags(),
    )
    if completed.returncode != 0:
        LOGGER.warning(
            "Could not inspect listening TCP ports via netstat. returncode=%s stderr=%s",
            completed.returncode,
            (completed.stderr or "").strip(),
        )
        return None

    for line in completed.stdout.splitlines():
        pid = _extract_pid_from_netstat_line(line=line, port=port)
        if pid is not None:
            return pid

    return None


def _extract_pid_from_netstat_line(*, line: str, port: int) -> int | None:
    chunks = line.split()
    if len(chunks) < 4:
        return None

    local_address = chunks[1]
    if not local_address.endswith(f":{port}"):
        return None

    pid_token = chunks[-1]
    if not pid_token.isdigit():
        return None

    return int(pid_token)


def _resolve_windows_process_name(*, pid: int) -> str | None:
    completed = subprocess.run(
        ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
        check=False,
        capture_output=True,
        text=True,
        creationflags=_windows_creation_flags(),
    )
    if completed.returncode != 0:
        LOGGER.warning(
            "Could not inspect process name for PID %s. returncode=%s stderr=%s",
            pid,
            completed.returncode,
            (completed.stderr or "").strip(),
        )
        return None

    first_line = next((line for line in completed.stdout.splitlines() if line.strip()), "")
    if not first_line:
        return None

    try:
        row = next(csv.reader([first_line]))
    except csv.Error:
        return None
    if not row:
        return None

    candidate = row[0].strip()
    if candidate.lower().endswith(".exe"):
        return candidate

    return None


def _resolve_windows_process_snapshot() -> list[WindowsProcessInfo]:
    command = (
        "Get-Process | "
        "Select-Object Id,ProcessName,Path | ConvertTo-Json -Compress"
    )
    completed = subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        creationflags=_windows_creation_flags(),
    )
    if completed.returncode != 0:
        LOGGER.warning(
            "Could not inspect Windows process tree. returncode=%s stderr=%s",
            completed.returncode,
            (completed.stderr or "").strip(),
        )
        return []

    raw_output = (completed.stdout or "").strip()
    if not raw_output:
        return []

    try:
        payload = json.loads(raw_output)
    except json.JSONDecodeError:
        LOGGER.warning("Could not parse Windows process snapshot output.")
        return []

    if isinstance(payload, dict):
        payload = [payload]
    if not isinstance(payload, list):
        return []

    result: list[WindowsProcessInfo] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        process_id = item.get("Id")
        name = str(item.get("ProcessName") or "").strip()
        executable_path = _normalize_optional_process_text(item.get("Path"))
        if not isinstance(process_id, int) or not name:
            continue
        result.append(
            WindowsProcessInfo(
                pid=process_id,
                name=_normalize_process_name(name),
                executable_path=executable_path,
            )
        )

    return result


def _matches_eimzo_identity(
    *,
    name: str,
    executable_path: str | None,
    command_line: str | None,
) -> bool:
    normalized_name = name.strip().casefold()
    normalized_executable_path = (executable_path or "").strip().casefold()
    normalized_command_line = (command_line or "").strip().casefold()

    if normalized_name == _EIMZO_PROCESS_NAME.casefold():
        return True

    if normalized_name in _EIMZO_PROCESS_NAME_ALIASES and not normalized_executable_path and not normalized_command_line:
        return True

    if normalized_name in {"javaw.exe", "java.exe"} and normalized_executable_path.startswith(_EIMZO_INSTALL_DIR):
        return True

    if normalized_name in {"javaw.exe", "java.exe"} and _EIMZO_INSTALL_DIR in normalized_command_line:
        return True

    if normalized_name in {"javaw.exe", "java.exe"}:
        return "e-imzo" in normalized_command_line or "e-imzo" in normalized_executable_path

    return False


def _normalize_optional_process_text(value: object) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _normalize_process_name(name: str) -> str:
    normalized = name.strip()
    if not normalized:
        return normalized
    if normalized.lower().endswith(".exe"):
        return normalized
    return f"{normalized}.exe"


def _windows_creation_flags() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _stop_process_via_powershell(*, pid: int) -> bool:
    command = f"Stop-Process -Id {pid} -Force -ErrorAction Stop"
    completed = subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
        creationflags=_windows_creation_flags(),
    )
    if completed.returncode == 0:
        return True

    LOGGER.warning(
        "Could not terminate PID %s via Stop-Process. returncode=%s stderr=%s",
        pid,
        completed.returncode,
        (completed.stderr or "").strip(),
    )
    return False
