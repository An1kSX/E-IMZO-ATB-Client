from __future__ import annotations

import logging
import os
from pathlib import Path

LOGGER = logging.getLogger(__name__)


class SingleInstanceLock:
    def __init__(self, lock_file_path: Path) -> None:
        self._lock_file_path = lock_file_path
        self._owner_pid_file_path = lock_file_path.with_suffix(".pid")
        self._lock_file = None
        self._locked = False

    def acquire(self) -> bool:
        if self._locked:
            return True

        self._lock_file_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock_file = self._lock_file_path.open("a+b")
        try:
            _lock_file(self._lock_file)
        except OSError:
            self._lock_file.close()
            self._lock_file = None
            return False

        self._locked = True
        self._lock_file.seek(0)
        self._lock_file.truncate()
        self._lock_file.write(str(os.getpid()).encode("ascii", errors="ignore"))
        self._lock_file.flush()
        self._write_owner_pid()
        return True

    def owner_pid(self) -> int | None:
        owner_pid = _read_pid_file(self._owner_pid_file_path)
        if owner_pid is not None:
            return owner_pid
        return _read_pid_file(self._lock_file_path)

    def release(self) -> None:
        if not self._locked or self._lock_file is None:
            return

        try:
            _unlock_file(self._lock_file)
        except OSError:
            pass
        self._lock_file.close()
        self._lock_file = None
        self._locked = False
        self._remove_owner_pid()

    def _write_owner_pid(self) -> None:
        try:
            self._owner_pid_file_path.write_text(str(os.getpid()), encoding="ascii")
        except OSError:
            LOGGER.exception("Could not write single-instance owner PID to %s.", self._owner_pid_file_path)

    def _remove_owner_pid(self) -> None:
        try:
            self._owner_pid_file_path.unlink(missing_ok=True)
        except OSError:
            LOGGER.exception("Could not remove single-instance owner PID file %s.", self._owner_pid_file_path)


def _read_pid_file(path: Path) -> int | None:
    try:
        raw_pid = path.read_text(encoding="ascii").strip()
    except OSError:
        return None

    if not raw_pid.isdigit():
        return None

    pid = int(raw_pid)
    if pid <= 0:
        return None
    return pid


def _lock_file(lock_file) -> None:
    if os.name == "nt":
        import msvcrt

        lock_file.seek(0)
        msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
        return

    import fcntl

    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock_file(lock_file) -> None:
    if os.name == "nt":
        import msvcrt

        lock_file.seek(0)
        msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
        return

    import fcntl

    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
