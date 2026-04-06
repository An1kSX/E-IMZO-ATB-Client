from __future__ import annotations

from dataclasses import dataclass
import json
import logging
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
from typing import Callable
import urllib.error
import urllib.request

from client import __version__
from client.bootstrap.config import AppConfig

LOGGER = logging.getLogger(__name__)
_DEFAULT_GITHUB_API = "https://api.github.com"
_DEFAULT_RELEASE_REPO = "An1kSX/E-IMZO-ATB-Client"
_USER_AGENT = "eimzo-atb-client-updater"


@dataclass(frozen=True, slots=True)
class ReleaseInfo:
    tag_name: str
    download_url: str


def maybe_start_self_update_from_github_release(*, config: AppConfig) -> bool:
    return maybe_start_self_update_from_github_release_with_notification(config=config)


def maybe_start_self_update_from_github_release_with_notification(
    *,
    config: AppConfig,
    notify_user: Callable[[ReleaseInfo], None] | None = None,
) -> bool:
    if not _can_self_update(config):
        return False

    release = _fetch_latest_release(
        repo=_DEFAULT_RELEASE_REPO,
        asset_name=config.auto_update_asset_name,
        timeout_seconds=config.auto_update_check_timeout_seconds,
    )
    if release is None:
        return False

    if not _is_newer_version(candidate=release.tag_name, current=__version__):
        return False

    current_executable = Path(sys.executable).resolve()
    updates_dir = config.runtime_dir / "updates"
    updates_dir.mkdir(parents=True, exist_ok=True)
    downloaded_file = updates_dir / f"{config.auto_update_asset_name}.download"
    updater_script = updates_dir / "apply-update.cmd"

    if not _download_file(url=release.download_url, destination=downloaded_file, timeout_seconds=config.auto_update_check_timeout_seconds):
        return False

    if notify_user is not None:
        try:
            notify_user(release)
        except Exception:
            LOGGER.exception("Could not show auto-update notification for release %s.", release.tag_name)

    _write_updater_script(
        script_path=updater_script,
        source_path=downloaded_file,
        target_path=current_executable,
        pid=os.getpid(),
    )
    if not _start_updater_script(updater_script):
        return False

    LOGGER.info(
        "Started self-update to %s from GitHub release. Current version=%s target=%s",
        release.tag_name,
        __version__,
        release.tag_name,
    )
    return True


def _can_self_update(config: AppConfig) -> bool:
    if platform.system() != "Windows":
        return False
    if not getattr(sys, "frozen", False):
        LOGGER.debug("Auto-update skipped because app is not running as frozen executable.")
        return False
    if not config.auto_update_enabled:
        return False
    return True


def _fetch_latest_release(*, repo: str, asset_name: str, timeout_seconds: float) -> ReleaseInfo | None:
    url = f"{_DEFAULT_GITHUB_API}/repos/{repo}/releases/latest"
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": _USER_AGENT,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as error:
        LOGGER.warning("Auto-update check failed: %s", error)
        return None

    tag_name = str(payload.get("tag_name") or "").strip()
    if not tag_name:
        return None

    download_url = _resolve_asset_download_url(payload=payload, asset_name=asset_name)
    if not download_url:
        LOGGER.warning("No release asset %r found in latest release %s.", asset_name, tag_name)
        return None

    return ReleaseInfo(tag_name=tag_name, download_url=download_url)


def _resolve_asset_download_url(*, payload: dict, asset_name: str) -> str | None:
    assets = payload.get("assets")
    if not isinstance(assets, list):
        return None

    normalized_name = asset_name.casefold()
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        name = str(asset.get("name") or "").strip()
        if name.casefold() != normalized_name:
            continue
        url = str(asset.get("browser_download_url") or "").strip()
        if url:
            return url

    return None


def _is_newer_version(*, candidate: str, current: str) -> bool:
    return _parse_version(candidate) > _parse_version(current)


def _parse_version(value: str) -> tuple[int, ...]:
    normalized = value.strip().lstrip("vV")
    numbers = [int(chunk) for chunk in re.findall(r"\d+", normalized)]
    if not numbers:
        return (0,)
    return tuple(numbers)


def _download_file(*, url: str, destination: Path, timeout_seconds: float) -> bool:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": _USER_AGENT},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            destination.write_bytes(response.read())
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        LOGGER.warning("Auto-update download failed from %s: %s", url, error)
        return False

    return True


def _write_updater_script(
    *,
    script_path: Path,
    source_path: Path,
    target_path: Path,
    pid: int,
) -> None:
    script_contents = (
        "@echo off\r\n"
        "setlocal\r\n"
        f"set \"PID={pid}\"\r\n"
        f"set \"SOURCE={source_path}\"\r\n"
        f"set \"TARGET={target_path}\"\r\n"
        "for /l %%i in (1,1,120) do (\r\n"
        "  tasklist /FI \"PID eq %PID%\" 2>NUL | find /I \"%PID%\" >NUL\r\n"
        "  if errorlevel 1 goto update\r\n"
        "  timeout /t 1 /nobreak >NUL\r\n"
        ")\r\n"
        ":update\r\n"
        "copy /Y \"%SOURCE%\" \"%TARGET%\" >NUL\r\n"
        "start \"\" \"%TARGET%\"\r\n"
        "del /Q \"%SOURCE%\" >NUL 2>&1\r\n"
        "del /Q \"%~f0\" >NUL 2>&1\r\n"
        "endlocal\r\n"
    )
    script_path.write_text(script_contents, encoding="utf-8")


def _start_updater_script(script_path: Path) -> bool:
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)
    try:
        subprocess.Popen(
            ["cmd.exe", "/c", str(script_path)],
            creationflags=creation_flags,
            close_fds=True,
        )
    except OSError as error:
        LOGGER.error("Could not start updater script %s: %s", script_path, error)
        return False

    return True
