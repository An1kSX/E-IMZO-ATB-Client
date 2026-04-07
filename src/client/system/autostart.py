from __future__ import annotations

import csv
import logging
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
from typing import Callable, Sequence

LOGGER = logging.getLogger(__name__)

_RUN_REGISTRY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
_RUN_VALUE_NAME = "E-IMZO ATB Client"
_EIMZO_ALL_USERS_STARTUP_LINK = Path(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\E-IMZO.lnk")


def sync_windows_auto_start(*, enabled: bool) -> None:
    if platform.system() != "Windows":
        return

    try:
        if enabled:
            command = resolve_windows_auto_start_command()
            changed = _upsert_windows_run_value(_RUN_VALUE_NAME, command)
            if changed:
                LOGGER.info("Enabled Windows auto-start for current user: %s", command)
            else:
                LOGGER.debug("Windows auto-start entry is already up to date.")
            return

        removed = _delete_windows_run_value(_RUN_VALUE_NAME)
        if removed:
            LOGGER.info("Disabled Windows auto-start for current user.")
        else:
            LOGGER.debug("Windows auto-start entry was already absent.")
    except OSError:
        LOGGER.exception("Could not synchronize Windows auto-start registration.")


def resolve_windows_auto_start_command(argv: Sequence[str] | None = None) -> str:
    launch_args = [str(argument) for argument in (argv or _resolve_current_launch_args()) if argument]
    if not launch_args:
        raise RuntimeError("Could not resolve launch command for Windows auto-start.")

    launch_args[0] = _normalize_interpreter_for_background_launch(launch_args[0])
    return subprocess.list2cmdline(launch_args)


def disable_windows_run_entries_by_command_fragment(*, fragment: str) -> int:
    if platform.system() != "Windows":
        return 0

    normalized_fragment = fragment.strip().casefold()
    if not normalized_fragment:
        return 0

    try:
        removed_count = _delete_windows_run_values_matching(
            lambda value_name, command: _matches_startup_fragment(
                value_name=value_name,
                command=command,
                fragments=(normalized_fragment,),
            )
        )
        removed_count += _delete_windows_startup_folder_entries_matching(
            fragments=(normalized_fragment,),
        )
        removed_count += _delete_windows_scheduled_tasks_matching(
            fragments=(normalized_fragment,),
        )
    except OSError:
        LOGGER.exception("Could not remove Windows auto-start entries for fragment %r.", fragment)
        return 0

    if removed_count:
        LOGGER.info(
            "Removed %s Windows auto-start entr%s matching fragment %r.",
            removed_count,
            "y" if removed_count == 1 else "ies",
            fragment,
        )
    else:
        LOGGER.info("No Windows auto-start entries matched fragment %r.", fragment)

    return removed_count


def disable_windows_run_entries_by_command_fragments(*, fragments: Sequence[str]) -> int:
    if platform.system() != "Windows":
        return 0

    normalized_fragments = [fragment.strip().casefold() for fragment in fragments if fragment.strip()]
    if not normalized_fragments:
        return 0

    try:
        removed_count = _delete_windows_run_values_matching(
            lambda value_name, command: _matches_startup_fragment(
                value_name=value_name,
                command=command,
                fragments=normalized_fragments,
            )
        )
        removed_count += _delete_windows_startup_folder_entries_matching(
            fragments=normalized_fragments,
        )
        removed_count += _delete_windows_scheduled_tasks_matching(
            fragments=normalized_fragments,
        )
    except OSError:
        LOGGER.exception("Could not remove Windows auto-start entries for fragments %r.", fragments)
        return 0

    if removed_count:
        LOGGER.info(
            "Removed %s Windows auto-start entr%s matching fragments %r.",
            removed_count,
            "y" if removed_count == 1 else "ies",
            fragments,
        )
    else:
        LOGGER.info("No Windows auto-start entries matched fragments %r.", fragments)

    return removed_count


def disable_known_eimzo_autostart() -> int:
    removed_count = disable_windows_run_entries_by_command_fragments(
        fragments=(
            "e-imzo.exe",
            "e-imzo.lnk",
            "javaw.exe",
            "java.exe",
            "e-imzo",
            r"c:\program files (x86)\e-imzo",
        ),
    )
    removed_count += _delete_known_eimzo_startup_links()
    return removed_count


def _resolve_current_launch_args() -> list[str]:
    orig_argv = getattr(sys, "orig_argv", None)
    if orig_argv:
        return list(orig_argv)

    if getattr(sys, "frozen", False):
        return [sys.executable]

    if sys.argv:
        return [sys.executable, *sys.argv]

    return [sys.executable]


def _normalize_interpreter_for_background_launch(executable: str) -> str:
    executable = _resolve_executable_path(executable)
    executable_path = Path(executable)
    executable_name = executable_path.name.lower()
    if not executable_name.startswith("python"):
        return executable

    if executable_name.startswith("pythonw"):
        return executable

    pythonw_path = executable_path.with_name("pythonw.exe")
    if pythonw_path.exists():
        return str(pythonw_path)

    return executable


def _resolve_executable_path(executable: str) -> str:
    candidate = Path(executable).expanduser()
    if candidate.is_absolute() or candidate.parent != Path():
        return str(candidate.resolve()) if candidate.exists() else executable

    resolved = shutil.which(executable)
    if resolved:
        return resolved

    return executable


def _upsert_windows_run_value(name: str, command: str) -> bool:
    winreg = _load_winreg()
    access = winreg.KEY_READ | winreg.KEY_WRITE
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, _RUN_REGISTRY_PATH, 0, access) as key:
        try:
            existing_value, _ = winreg.QueryValueEx(key, name)
        except FileNotFoundError:
            existing_value = None

        if existing_value == command:
            return False

        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, command)
        return True


def _delete_windows_run_value(name: str) -> bool:
    winreg = _load_winreg()
    access = winreg.KEY_READ | winreg.KEY_WRITE
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, _RUN_REGISTRY_PATH, 0, access) as key:
        try:
            winreg.DeleteValue(key, name)
        except FileNotFoundError:
            return False

    return True


def _delete_windows_run_values_matching(predicate: Callable[[str, object], bool]) -> int:
    winreg = _load_winreg()
    access = winreg.KEY_READ | winreg.KEY_WRITE
    removed_count = 0
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, _RUN_REGISTRY_PATH, 0, access) as key:
        value_names: list[str] = []
        index = 0
        while True:
            try:
                value_name, command, _value_type = winreg.EnumValue(key, index)
            except OSError:
                break
            value_names.append(value_name)
            index += 1

        for value_name in value_names:
            try:
                command, _value_type = winreg.QueryValueEx(key, value_name)
            except FileNotFoundError:
                continue
            if not predicate(value_name, command):
                continue
            winreg.DeleteValue(key, value_name)
            removed_count += 1

    return removed_count


def _matches_startup_fragment(*, value_name: str, command: object, fragments: Sequence[str]) -> bool:
    normalized_value_name = value_name.casefold()
    normalized_command = command.casefold() if isinstance(command, str) else ""
    return any(
        fragment in normalized_value_name or fragment in normalized_command
        for fragment in fragments
    )


def _delete_windows_startup_folder_entries_matching(*, fragments: Sequence[str]) -> int:
    removed_count = 0
    for startup_dir in _iter_windows_startup_directories():
        if not startup_dir.exists():
            continue
        for entry in startup_dir.iterdir():
            if not entry.is_file():
                continue
            entry_name = entry.name.casefold()
            if not any(fragment in entry_name for fragment in fragments):
                continue
            try:
                entry.unlink()
            except OSError:
                LOGGER.exception("Could not remove Windows startup entry %s.", entry)
                continue
            removed_count += 1

    return removed_count


def _iter_windows_startup_directories() -> list[Path]:
    directories: list[Path] = []
    appdata = os.getenv("APPDATA")
    if appdata:
        directories.append(Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")

    program_data = os.getenv("ProgramData")
    if program_data:
        directories.append(Path(program_data) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp")

    return directories


def _delete_known_eimzo_startup_links() -> int:
    if platform.system() != "Windows":
        return 0

    removed_count = 0
    candidate_paths = {_EIMZO_ALL_USERS_STARTUP_LINK}
    for startup_dir in _iter_windows_startup_directories():
        candidate_paths.add(startup_dir / "E-IMZO.lnk")

    for path in candidate_paths:
        if _delete_path_with_optional_elevation(path):
            removed_count += 1

    return removed_count


def _delete_windows_scheduled_tasks_matching(*, fragments: Sequence[str]) -> int:
    completed = subprocess.run(
        ["schtasks", "/Query", "/V", "/FO", "CSV", "/NH"],
        check=False,
        capture_output=True,
        text=True,
        creationflags=_windows_creation_flags(),
    )
    if completed.returncode != 0:
        LOGGER.warning(
            "Could not inspect Windows scheduled tasks. returncode=%s stderr=%s",
            completed.returncode,
            (completed.stderr or "").strip(),
        )
        return 0

    removed_count = 0
    reader = csv.reader(line for line in completed.stdout.splitlines() if line.strip())
    task_names: list[str] = []
    for row in reader:
        if not row:
            continue
        task_name = row[0].strip()
        if not task_name:
            continue
        normalized_row_values = [value.strip().casefold() for value in row if value.strip()]
        if any(
            fragment in value
            for fragment in fragments
            for value in normalized_row_values
        ):
            task_names.append(task_name)

    for task_name in task_names:
        delete_completed = subprocess.run(
            ["schtasks", "/Delete", "/TN", task_name, "/F"],
            check=False,
            capture_output=True,
            text=True,
            creationflags=_windows_creation_flags(),
        )
        if delete_completed.returncode == 0:
            removed_count += 1
            continue
        LOGGER.warning(
            "Could not remove scheduled task %s. returncode=%s stderr=%s",
            task_name,
            delete_completed.returncode,
            (delete_completed.stderr or "").strip(),
        )

    return removed_count


def _windows_creation_flags() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _delete_path_with_optional_elevation(path: Path) -> bool:
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return False
    except PermissionError:
        LOGGER.warning("Permission denied while removing %s. Requesting elevation.", path)
        return _delete_path_via_elevated_powershell(path)
    except OSError:
        LOGGER.exception("Could not remove %s.", path)
        return False


def _delete_path_via_elevated_powershell(path: Path) -> bool:
    escaped_path = str(path).replace("'", "''")
    inner_command = f"Remove-Item -LiteralPath '{escaped_path}' -Force"
    outer_command = (
        "Start-Process powershell "
        "-Verb RunAs "
        "-Wait "
        f"-ArgumentList '-NoLogo','-NoProfile','-NonInteractive','-Command','{inner_command}'"
    )
    completed = subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", outer_command],
        check=False,
        capture_output=True,
        text=True,
        creationflags=_windows_creation_flags(),
    )
    if completed.returncode != 0:
        LOGGER.warning(
            "Could not launch elevated removal for %s. returncode=%s stderr=%s",
            path,
            completed.returncode,
            (completed.stderr or "").strip(),
        )
        return False

    return not path.exists()


def _load_winreg():
    import winreg

    return winreg
