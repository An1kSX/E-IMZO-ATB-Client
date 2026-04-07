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
import time
from typing import Callable, Literal
import urllib.error
import urllib.request

from client import __version__
from client.bootstrap.config import AppConfig

LOGGER = logging.getLogger(__name__)
_DEFAULT_GITHUB_API = "https://api.github.com"
_DEFAULT_RELEASE_REPO = "An1kSX/E-IMZO-ATB-Client"
_USER_AGENT = "eimzo-atb-client-updater"
_FAILED_UPDATE_RETRY_COOLDOWN_SECONDS = 1800.0
_UPDATER_START_TIMEOUT_SECONDS = 5.0
_UPDATER_START_POLL_INTERVAL_SECONDS = 0.1


@dataclass(frozen=True, slots=True)
class UpdateNotification:
    stage: Literal["downloading", "installing"]
    release: "ReleaseInfo"


@dataclass(frozen=True, slots=True)
class UpdateState:
    target_version: str
    started_at: float


@dataclass(frozen=True, slots=True)
class ReleaseInfo:
    tag_name: str
    download_url: str


def maybe_start_self_update_from_github_release(*, config: AppConfig) -> bool:
    return maybe_start_self_update_from_github_release_with_notification(config=config)


def maybe_start_self_update_from_github_release_with_notification(
    *,
    config: AppConfig,
    notify_user: Callable[[UpdateNotification], None] | None = None,
) -> bool:
    LOGGER.info(
        "Starting auto-update check. current_version=%s repo=%s asset_name=%s frozen=%s platform=%s",
        __version__,
        _DEFAULT_RELEASE_REPO,
        config.auto_update_asset_name,
        getattr(sys, "frozen", False),
        platform.system(),
    )
    if not _can_self_update(config):
        LOGGER.info("Auto-update check stopped because self-update is not available in this runtime.")
        return False

    state_file_path = _build_update_state_path(config.runtime_dir)
    if _clear_update_state_if_applied(state_file_path=state_file_path):
        LOGGER.info("Cleared pending auto-update state after successful version change.")

    release = _fetch_latest_release(
        repo=_DEFAULT_RELEASE_REPO,
        asset_name=config.auto_update_asset_name,
        timeout_seconds=config.auto_update_check_timeout_seconds,
    )
    if release is None:
        LOGGER.info("Auto-update check finished without a usable release.")
        return False

    LOGGER.info(
        "Resolved latest GitHub release. tag_name=%s download_url=%s",
        release.tag_name,
        release.download_url,
    )
    if not _is_newer_version(candidate=release.tag_name, current=__version__):
        LOGGER.info(
            "Auto-update skipped because the latest release is not newer. current_version=%s latest_version=%s",
            __version__,
            release.tag_name,
        )
        return False

    if _should_skip_repeated_failed_update_attempt(
        state_file_path=state_file_path,
        release=release,
        current_version=__version__,
    ):
        LOGGER.warning(
            "Skipping repeated auto-update attempt to %s because a recent install attempt did not complete.",
            release.tag_name,
        )
        return False

    current_executable = Path(sys.executable).resolve()
    updates_dir = config.runtime_dir / "updates"
    updates_dir.mkdir(parents=True, exist_ok=True)
    downloaded_file = updates_dir / f"{config.auto_update_asset_name}.new"
    updater_script = updates_dir / "apply-update.cmd"
    updater_log_file = updates_dir / "apply-update.log"
    updater_start_marker = updates_dir / "apply-update.started"
    LOGGER.info(
        "Preparing auto-update files. executable=%s downloaded_file=%s updater_script=%s updater_log=%s updater_marker=%s",
        current_executable,
        downloaded_file,
        updater_script,
        updater_log_file,
        updater_start_marker,
    )

    for stale_file in (updater_log_file, updater_start_marker):
        try:
            stale_file.unlink()
        except FileNotFoundError:
            pass
        except OSError as error:
            LOGGER.warning("Could not remove stale updater file %s: %s", stale_file, error)

    if notify_user is not None:
        try:
            notify_user(UpdateNotification(stage="downloading", release=release))
        except Exception:
            LOGGER.exception("Could not show auto-update download notification for release %s.", release.tag_name)

    if not _download_file(url=release.download_url, destination=downloaded_file, timeout_seconds=config.auto_update_check_timeout_seconds):
        LOGGER.warning("Auto-update aborted because the release asset could not be downloaded.")
        return False

    if notify_user is not None:
        try:
            notify_user(UpdateNotification(stage="installing", release=release))
        except Exception:
            LOGGER.exception("Could not show auto-update notification for release %s.", release.tag_name)

    try:
        _write_updater_script(
            script_path=updater_script,
            source_path=downloaded_file,
            target_path=current_executable,
            pid=os.getpid(),
            log_path=updater_log_file,
            start_marker_path=updater_start_marker,
        )
    except OSError as error:
        LOGGER.error("Could not write updater script %s: %s", updater_script, error)
        return False

    if not _start_updater_script(updater_script, updater_start_marker):
        LOGGER.error("Auto-update aborted because updater script could not be started.")
        return False

    _save_update_state(
        state_file_path=state_file_path,
        state=UpdateState(target_version=release.tag_name, started_at=time.time()),
    )

    LOGGER.info(
        "Started self-update to %s from GitHub release. Current version=%s target=%s",
        release.tag_name,
        __version__,
        release.tag_name,
    )
    return True


def _can_self_update(config: AppConfig) -> bool:
    if platform.system() != "Windows":
        LOGGER.info("Auto-update disabled because the current platform is not Windows.")
        return False
    if not getattr(sys, "frozen", False):
        LOGGER.info("Auto-update skipped because app is not running as frozen executable.")
        return False
    if not config.auto_update_enabled:
        LOGGER.info("Auto-update disabled by configuration.")
        return False
    return True


def _fetch_latest_release(*, repo: str, asset_name: str, timeout_seconds: float) -> ReleaseInfo | None:
    url = f"{_DEFAULT_GITHUB_API}/repos/{repo}/releases/latest"
    LOGGER.info("Requesting latest GitHub release metadata from %s", url)
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
        LOGGER.warning("Latest GitHub release response did not contain tag_name.")
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
    LOGGER.info("Downloading auto-update asset from %s to %s", url, destination)
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

    try:
        file_size = destination.stat().st_size
    except OSError:
        file_size = -1
    LOGGER.info("Downloaded auto-update asset successfully. destination=%s size_bytes=%s", destination, file_size)
    return True


def _build_update_state_path(runtime_dir: Path) -> Path:
    return runtime_dir / "updates" / "update-state.json"


def _save_update_state(*, state_file_path: Path, state: UpdateState) -> None:
    state_file_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "target_version": state.target_version,
        "started_at": state.started_at,
    }
    state_file_path.write_text(json.dumps(payload), encoding="utf-8")


def _load_update_state(*, state_file_path: Path) -> UpdateState | None:
    if not state_file_path.exists():
        return None

    try:
        payload = json.loads(state_file_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    target_version = str(payload.get("target_version") or "").strip()
    started_at = payload.get("started_at")
    if not target_version or not isinstance(started_at, (int, float)):
        return None

    return UpdateState(target_version=target_version, started_at=float(started_at))


def _clear_update_state_if_applied(*, state_file_path: Path) -> bool:
    state = _load_update_state(state_file_path=state_file_path)
    if state is None:
        return False

    if not _is_newer_version(candidate=state.target_version, current=__version__):
        try:
            state_file_path.unlink()
        except FileNotFoundError:
            return False
        except OSError:
            return False
        return True

    return False


def _should_skip_repeated_failed_update_attempt(
    *,
    state_file_path: Path,
    release: ReleaseInfo,
    current_version: str,
) -> bool:
    state = _load_update_state(state_file_path=state_file_path)
    if state is None:
        return False

    if state.target_version != release.tag_name:
        return False

    if not _is_newer_version(candidate=release.tag_name, current=current_version):
        return False

    return (time.time() - state.started_at) < _FAILED_UPDATE_RETRY_COOLDOWN_SECONDS


def _write_updater_script(
    *,
    script_path: Path,
    source_path: Path,
    target_path: Path,
    pid: int,
    log_path: Path,
    start_marker_path: Path,
) -> None:
    source_literal = _to_cmd_literal(str(source_path))
    target_literal = _to_cmd_literal(str(target_path))
    log_literal = _to_cmd_literal(str(log_path))
    start_marker_literal = _to_cmd_literal(str(start_marker_path))
    script_contents = (
        "@echo off\n"
        "setlocal EnableExtensions EnableDelayedExpansion\n"
        f"set \"TargetPid={pid}\"\n"
        f"set \"SourcePath={source_literal}\"\n"
        f"set \"TargetPath={target_literal}\"\n"
        f"set \"LogPath={log_literal}\"\n"
        f"set \"StartMarkerPath={start_marker_literal}\"\n"
        "set \"CopySucceeded=0\"\n"
        "\n"
        "> \"%StartMarkerPath%\" echo started\n"
        "call :WriteUpdateLog Updater script started. targetPid=%TargetPid% source=%SourcePath% target=%TargetPath%\n"
        "\n"
        "for /L %%I in (0,1,119) do (\n"
        "    tasklist /FI \"PID eq %TargetPid%\" 2>NUL | findstr /R /C:\"\\<%TargetPid%\\>\" >NUL\n"
        "    if errorlevel 1 (\n"
        "        call :WriteUpdateLog Target process is no longer running.\n"
        "        goto AfterWait\n"
        "    )\n"
        "    call :WriteUpdateLog Waiting for target process to exit. attempt=%%I\n"
        "    timeout /t 1 /nobreak >NUL\n"
        ")\n"
        "\n"
        ":AfterWait\n"
        "for /L %%I in (0,1,39) do (\n"
        "    copy /Y \"%SourcePath%\" \"%TargetPath%\" >NUL 2>&1\n"
        "    if not errorlevel 1 (\n"
        "        set \"CopySucceeded=1\"\n"
        "        call :WriteUpdateLog Copied update payload successfully. attempt=%%I\n"
        "        goto AfterCopy\n"
        "    )\n"
        "    call :WriteUpdateLog Copy attempt failed. attempt=%%I error=!errorlevel!\n"
        "    timeout /t 1 /nobreak >NUL\n"
        ")\n"
        "\n"
        ":AfterCopy\n"
        "start \"\" \"%TargetPath%\" >NUL 2>&1\n"
        "if errorlevel 1 (\n"
        "    call :WriteUpdateLog Failed to start updated executable. error=%errorlevel%\n"
        ") else (\n"
        "    call :WriteUpdateLog Started updated executable successfully.\n"
        ")\n"
        "\n"
        "if \"%CopySucceeded%\"==\"1\" (\n"
        "    del /F /Q \"%SourcePath%\" >NUL 2>&1\n"
        "    if errorlevel 1 (\n"
        "        call :WriteUpdateLog Failed to remove temporary update payload. error=%errorlevel%\n"
        "    ) else (\n"
        "        call :WriteUpdateLog Removed temporary update payload.\n"
        "    )\n"
        ") else (\n"
        "    call :WriteUpdateLog Copy never succeeded; target executable was not replaced.\n"
        ")\n"
        "\n"
        "call :WriteUpdateLog Updater script finished.\n"
        "start \"\" /B cmd /C del /F /Q \"%~f0\" >NUL 2>&1\n"
        "exit /b 0\n"
        "\n"
        ":WriteUpdateLog\n"
        ">> \"%LogPath%\" echo [%date% %time%] [UPDATER] %*\n"
        "exit /b 0\n"
    )
    script_path.write_text(script_contents, encoding="utf-8")
    LOGGER.info("Wrote updater script to %s", script_path)


def _start_updater_script(script_path: Path, start_marker_path: Path) -> bool:
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    LOGGER.info("Starting updater script %s", script_path)
    try:
        process = subprocess.Popen(
            [
                "cmd.exe",
                "/c",
                str(script_path),
            ],
            creationflags=creation_flags,
            close_fds=True,
        )
    except OSError as error:
        LOGGER.error("Could not start updater script %s: %s", script_path, error)
        return False

    deadline = time.monotonic() + _UPDATER_START_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if start_marker_path.exists():
            LOGGER.info("Updater script confirmed startup via marker file: %s", start_marker_path)
            LOGGER.info("Updater script process started successfully: %s", script_path)
            return True

        if process.poll() is not None:
            LOGGER.error(
                "Updater script process exited before creating startup marker. exit_code=%s script=%s",
                process.returncode,
                script_path,
            )
            return False

        time.sleep(_UPDATER_START_POLL_INTERVAL_SECONDS)

    LOGGER.error(
        "Updater script did not create startup marker within %.1f seconds: %s",
        _UPDATER_START_TIMEOUT_SECONDS,
        start_marker_path,
    )
    return False
def _to_cmd_literal(value: str) -> str:
    return value.replace('"', '""')
