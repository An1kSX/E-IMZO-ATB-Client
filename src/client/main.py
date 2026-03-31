from __future__ import annotations

import asyncio
import logging
import platform

from client.app import run_app
from client.bootstrap.config import AppConfig, ConfigurationError
from client.bootstrap.logging import configure_logging
from client.system.tray_icon import WindowsTrayIcon


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
    tray_icon = WindowsTrayIcon(on_exit_request=lambda: loop.call_soon_threadsafe(shutdown_event.set))
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
            await asyncio.gather(app_task, return_exceptions=True)
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


if __name__ == "__main__":
    main()
