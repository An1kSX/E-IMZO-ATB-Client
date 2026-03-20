from __future__ import annotations

import asyncio
import logging
import platform

from client.app import run_app
from client.bootstrap.config import AppConfig, ConfigurationError
from client.bootstrap.logging import configure_logging


def main() -> None:
    _install_windows_event_loop()

    try:
        config = AppConfig.from_env()
    except ConfigurationError as error:
        configure_logging("ERROR")
        logging.getLogger(__name__).error("%s", error)
        raise SystemExit(2) from error

    configure_logging(config.log_level)

    try:
        asyncio.run(run_app(config))
    except KeyboardInterrupt:
        logging.getLogger(__name__).info("Local WSS service stopped by user.")
    except Exception:
        logging.getLogger(__name__).exception("Local WSS service stopped because of an unexpected error.")
        raise SystemExit(1)


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
