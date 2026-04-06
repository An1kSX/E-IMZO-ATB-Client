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
    if not _can_self_update(config):
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
        return False

    if not _is_newer_version(candidate=release.tag_name, current=__version__):
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
    updater_script = updates_dir / "apply-update.ps1"

    if notify_user is not None:
        try:
            notify_user(UpdateNotification(stage="downloading", release=release))
        except Exception:
            LOGGER.exception("Could not show auto-update download notification for release %s.", release.tag_name)

    if not _download_file(url=release.download_url, destination=downloaded_file, timeout_seconds=config.auto_update_check_timeout_seconds):
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
        )
    except OSError as error:
        LOGGER.error("Could not write updater script %s: %s", updater_script, error)
        return False

    if not _start_updater_script(updater_script):
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
) -> None:
    source_literal = _to_powershell_literal(str(source_path))
    target_literal = _to_powershell_literal(str(target_path))
    script_contents = (
        f"$TargetPid = {pid}\n"
        f"$SourcePath = '{source_literal}'\n"
        f"$TargetPath = '{target_literal}'\n"
        "$CopySucceeded = $false\n"
        "\n"
        "for ($attempt = 0; $attempt -lt 120; $attempt++) {\n"
        "    if (-not (Get-Process -Id $TargetPid -ErrorAction SilentlyContinue)) {\n"
        "        break\n"
        "    }\n"
        "    Start-Sleep -Seconds 1\n"
        "}\n"
        "\n"
        "for ($attempt = 0; $attempt -lt 40; $attempt++) {\n"
        "    try {\n"
        "        Copy-Item -LiteralPath $SourcePath -Destination $TargetPath -Force\n"
        "        $CopySucceeded = $true\n"
        "        break\n"
        "    } catch {\n"
        "        Start-Sleep -Seconds 1\n"
        "    }\n"
        "}\n"
        "\n"
        "try {\n"
        "    Start-Process -FilePath $TargetPath | Out-Null\n"
        "} catch {\n"
        "}\n"
        "\n"
        "if ($CopySucceeded) {\n"
        "    try {\n"
        "        Remove-Item -LiteralPath $SourcePath -Force -ErrorAction SilentlyContinue\n"
        "    } catch {\n"
        "    }\n"
        "}\n"
        "\n"
        "$ScriptPath = $MyInvocation.MyCommand.Path\n"
        "Start-Sleep -Milliseconds 200\n"
        "try {\n"
        "    Remove-Item -LiteralPath $ScriptPath -Force -ErrorAction SilentlyContinue\n"
        "} catch {\n"
        "}\n"
    )
    script_path.write_text(script_contents, encoding="utf-8")


def _start_updater_script(script_path: Path) -> bool:
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)
    try:
        subprocess.Popen(
            [
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-WindowStyle",
                "Hidden",
                "-File",
                str(script_path),
            ],
            creationflags=creation_flags,
            close_fds=True,
        )
    except OSError as error:
        LOGGER.error("Could not start updater script %s: %s", script_path, error)
        return False

    return True


def _to_powershell_literal(value: str) -> str:
    return value.replace("'", "''")
