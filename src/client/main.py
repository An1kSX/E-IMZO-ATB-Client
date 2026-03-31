from __future__ import annotations

import asyncio
import os
import logging
import platform

from client.app import run_app
from client.bootstrap.config import AppConfig, ConfigurationError
from client.bootstrap.logging import configure_logging
from client.system.app_icon import resolve_app_icon_path
from client.system.autostart import sync_windows_auto_start
from client.system.tray_icon import WindowsTrayIcon

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
    sync_windows_auto_start(enabled=config.windows_auto_start_enabled)

    try:
        asyncio.run(_run_with_system_tray(config))
    except KeyboardInterrupt:
        logging.getLogger(__name__).info("Local WSS service stopped by user.")
    except Exception:
        logging.getLogger(__name__).exception("Local WSS service stopped because of an unexpected error.")
        raise SystemExit(1)


async def _run_with_system_tray(config: AppConfig) -> None:
    if platform.system() != "Windows":
        await run_app(config)
        return

    loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event()
    tray_icon = WindowsTrayIcon(
        on_exit_request=lambda: loop.call_soon_threadsafe(shutdown_event.set),
        icon_path=resolve_app_icon_path(),
    )
    app_task = asyncio.create_task(run_app(config), name="run-app")
    shutdown_task = asyncio.create_task(shutdown_event.wait(), name="wait-for-tray-exit")

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
            {app_task, shutdown_task},
            return_when=asyncio.FIRST_COMPLETED,
        )

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
                _force_process_exit(0)
            return

        shutdown_task.cancel()
        await asyncio.gather(shutdown_task, return_exceptions=True)
        await app_task
    finally:
        shutdown_task.cancel()
        await asyncio.gather(shutdown_task, return_exceptions=True)
        tray_icon.stop()


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


if __name__ == "__main__":
    main()
