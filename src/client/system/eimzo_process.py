from __future__ import annotations

from dataclasses import dataclass
import csv
import logging
import platform
import subprocess

LOGGER = logging.getLogger(__name__)
_EIMZO_PROCESS_NAME = "E-IMZO.exe"


@dataclass(frozen=True, slots=True)
class ListeningProcess:
    pid: int
    name: str


def find_listening_process_by_port(*, port: int) -> ListeningProcess | None:
    if platform.system() != "Windows":
        return None

    pid = _resolve_windows_pid_by_port(port=port)
    if pid is None:
        return None

    name = _resolve_windows_process_name(pid=pid)
    if name is None:
        return None

    return ListeningProcess(pid=pid, name=name)


def terminate_process_by_pid(*, pid: int) -> bool:
    if platform.system() != "Windows" or pid <= 0:
        return False

    completed = subprocess.run(
        ["taskkill", "/PID", str(pid), "/F"],
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


def is_eimzo_process_name(name: str) -> bool:
    return name.strip().casefold() == _EIMZO_PROCESS_NAME.casefold()


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


def _windows_creation_flags() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0)
