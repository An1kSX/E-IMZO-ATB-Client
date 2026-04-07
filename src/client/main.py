from __future__ import annotations

import asyncio
import os
import logging
import platform
from pathlib import Path
import sys
import threading

from client import __version__
from client.app import run_app
from client.bootstrap.config import (
    AppConfig,
    ConfigurationError,
    clear_saved_api_eimzo_url,
    prompt_and_save_api_eimzo_url,
)
from client.bootstrap.logging import configure_logging
from client.system.app_icon import resolve_app_icon_path
from client.system.autostart import sync_windows_auto_start
from client.system.eimzo_process import launch_installed_eimzo
from client.system.single_instance import SingleInstanceLock
from client.system.tray_icon import WindowsTrayIcon
from client.system.updates import (
    UpdateNotification,
    maybe_start_self_update_from_github_release_with_notification,
)
from client.ui import show_info_message

_TRAY_SHUTDOWN_TIMEOUT_SECONDS = 5.0


def main() -> None:
    _install_windows_event_loop()

    try:
        config = AppConfig.from_env()
    except ConfigurationError as error:
        configure_logging("ERROR")
        logging.getLogger(__name__).error("%s", error)
        raise SystemExit(2) from error

    configure_logging(
        config.log_level,
        runtime_dir=config.runtime_dir,
        log_dir=config.log_dir,
    )
    logging.getLogger(__name__).info(
        "Starting E-IMZO ATB Client. version=%s executable=%s cwd=%s",
        __version__,
        Path(sys.executable).resolve(),
        Path.cwd(),
    )
    sync_windows_auto_start(enabled=config.windows_auto_start_enabled)
    instance_lock = SingleInstanceLock(config.runtime_dir / "instance.lock")
    if not instance_lock.acquire():
        logging.getLogger(__name__).warning("Another E-IMZO ATB Client instance is already running.")
        try:
            show_info_message(
                title="E-IMZO ATB Client уже запущен",
                message="Нельзя запускать несколько экземпляров одновременно. Закройте текущий экземпляр и попробуйте снова.",
            )
        except Exception:
            logging.getLogger(__name__).exception("Could not show duplicate-instance warning dialog.")
        raise SystemExit(0)

    try:
        if maybe_start_self_update_from_github_release_with_notification(
            config=config,
            notify_user=_show_auto_update_started_message,
        ):
            logging.getLogger(__name__).info("Auto-update started. Exiting current process.")
            return
        try:
            asyncio.run(_run_with_system_tray(config))
        except KeyboardInterrupt:
            logging.getLogger(__name__).info("Local WSS service stopped by user.")
        except Exception:
            logging.getLogger(__name__).exception("Local WSS service stopped because of an unexpected error.")
            raise SystemExit(1)
    finally:
        instance_lock.release()


async def _run_with_system_tray(config: AppConfig) -> None:
    if platform.system() != "Windows":
        await run_app(config)
        return

    loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event()
    launch_eimzo_after_shutdown = threading.Event()
    tray_icon = WindowsTrayIcon(
        on_exit_request=lambda: loop.call_soon_threadsafe(shutdown_event.set),
        on_exit_and_launch_eimzo_request=lambda: _request_exit_and_launch_eimzo(
            loop=loop,
            shutdown_event=shutdown_event,
            launch_eimzo_after_shutdown=launch_eimzo_after_shutdown,
        ),
        on_configure_api_url_request=lambda: _configure_saved_api_url(config.runtime_dir),
        on_reset_api_url_request=lambda: _reset_saved_api_url(config.runtime_dir),
        icon_path=resolve_app_icon_path(),
    )
    app_task = asyncio.create_task(run_app(config), name="run-app")
    shutdown_task = asyncio.create_task(shutdown_event.wait(), name="wait-for-tray-exit")
    auto_update_task = asyncio.create_task(
        _run_periodic_auto_update_checks(config, shutdown_event),
        name="periodic-auto-update",
    )

    try:
        try:
            tray_icon.start()
        except Exception:
            logging.getLogger(__name__).exception(
                "System tray icon failed to start. Continuing without tray integration."
            )
            await app_task
            return

        done, pending = await asyncio.wait(
            {app_task, shutdown_task, auto_update_task},
            return_when=asyncio.FIRST_COMPLETED,
        )

        if auto_update_task in done:
            update_started = auto_update_task.result()
            if update_started:
                logging.getLogger(__name__).info("Stopping application because auto-update was started.")
                app_task.cancel()
                try:
                    await asyncio.wait_for(
                        asyncio.gather(app_task, return_exceptions=True),
                        timeout=_TRAY_SHUTDOWN_TIMEOUT_SECONDS,
                    )
                except asyncio.TimeoutError:
                    logging.getLogger(__name__).error(
                        "Graceful shutdown timed out after %.1f seconds during auto-update. Forcing process exit.",
                        _TRAY_SHUTDOWN_TIMEOUT_SECONDS,
                    )
                    tray_icon.stop()
                    _force_process_exit(0)
                return

        if shutdown_task in done:
            logging.getLogger(__name__).info("Stopping application because of tray exit request.")
            app_task.cancel()
            try:
                await asyncio.wait_for(
                    asyncio.gather(app_task, return_exceptions=True),
                    timeout=_TRAY_SHUTDOWN_TIMEOUT_SECONDS,
                )
            except asyncio.TimeoutError:
                logging.getLogger(__name__).error(
                    "Graceful shutdown timed out after %.1f seconds. Forcing process exit.",
                    _TRAY_SHUTDOWN_TIMEOUT_SECONDS,
                )
                tray_icon.stop()
                if launch_eimzo_after_shutdown.is_set():
                    _launch_eimzo_after_shutdown()
                _force_process_exit(0)
            if launch_eimzo_after_shutdown.is_set():
                _launch_eimzo_after_shutdown()
            return

        shutdown_task.cancel()
        await asyncio.gather(shutdown_task, return_exceptions=True)
        auto_update_task.cancel()
        await asyncio.gather(auto_update_task, return_exceptions=True)
        await app_task
    finally:
        shutdown_task.cancel()
        await asyncio.gather(shutdown_task, return_exceptions=True)
        auto_update_task.cancel()
        await asyncio.gather(auto_update_task, return_exceptions=True)
        tray_icon.stop()


async def _run_periodic_auto_update_checks(
    config: AppConfig,
    shutdown_event: asyncio.Event,
) -> bool:
    if not getattr(config, "auto_update_enabled", True):
        return False

    check_interval_seconds = max(1.0, float(getattr(config, "auto_update_check_interval_seconds", 60.0)))
    while not shutdown_event.is_set():
        try:
            await asyncio.sleep(check_interval_seconds)
        except asyncio.CancelledError:
            raise

        if shutdown_event.is_set():
            return False

        update_started = await asyncio.to_thread(
            maybe_start_self_update_from_github_release_with_notification,
            config=config,
            notify_user=_show_auto_update_started_message,
        )
        if update_started:
            shutdown_event.set()
            return True

    return False


def _install_windows_event_loop() -> None:
    if platform.system() != "Windows":
        return

    try:
        import winloop
    except ImportError:
        return

    install = getattr(winloop, "install", None)
    if callable(install):
        install()


def _force_process_exit(code: int) -> None:
    os._exit(code)


def _request_exit_and_launch_eimzo(
    *,
    loop: asyncio.AbstractEventLoop,
    shutdown_event: asyncio.Event,
    launch_eimzo_after_shutdown: threading.Event,
) -> None:
    launch_eimzo_after_shutdown.set()
    loop.call_soon_threadsafe(shutdown_event.set)


def _launch_eimzo_after_shutdown() -> None:
    if launch_installed_eimzo():
        logging.getLogger(__name__).info("Launched E-IMZO after tray shutdown request.")
        return

    logging.getLogger(__name__).error("Failed to launch E-IMZO after tray shutdown request.")
    show_info_message(
        title="Не удалось запустить E-IMZO",
        message=(
            "Клиент завершил работу, но запустить установленный E-IMZO автоматически не удалось.\n\n"
            "Проверьте, что E-IMZO установлен в C:\\Program Files (x86)\\E-IMZO, и запустите его вручную."
        ),
    )


def _show_auto_update_started_message(notification: UpdateNotification) -> None:
    if notification.stage == "downloading":
        show_info_message(
            title="Найдено обновление",
            message=(
                f"Найдена новая версия {notification.release.tag_name}.\n\n"
                "Сейчас E-IMZO ATB Client начнет скачивание обновления."
            ),
        )
        return

    show_info_message(
        title="Обновление скачано",
        message=(
            f"Новая версия {notification.release.tag_name} уже скачана.\n\n"
            "Сейчас E-IMZO ATB Client будет перезапущен для установки обновления."
        ),
    )


def _configure_saved_api_url(runtime_dir: Path) -> None:
    api_url = prompt_and_save_api_eimzo_url(runtime_dir=runtime_dir)
    if api_url is None:
        return

    show_info_message(
        title="Настройка сохранена",
        message=_build_saved_url_message(
            body=f"Новый URL E-IMZO API сохранен:\n{api_url}",
        ),
    )


def _reset_saved_api_url(runtime_dir: Path) -> None:
    clear_saved_api_eimzo_url(runtime_dir=runtime_dir)
    show_info_message(
        title="Настройка сброшена",
        message=_build_saved_url_message(
            body="Сохраненный URL E-IMZO API удален.",
        ),
    )


def _build_saved_url_message(*, body: str) -> str:
    if os.getenv("API_EIMZO_URL"):
        return (
            f"{body}\n\n"
            "Сейчас приложение использует значение API_EIMZO_URL из переменных среды. "
            "Сохраненный URL начнет работать после удаления этой переменной."
        )

    return f"{body}\n\nПерезапустите приложение, чтобы применить изменения."


if __name__ == "__main__":
    main()
