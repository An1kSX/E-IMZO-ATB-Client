from __future__ import annotations

import os
from pathlib import Path


class SingleInstanceLock:
    def __init__(self, lock_file_path: Path) -> None:
        self._lock_file_path = lock_file_path
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
        return True

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
