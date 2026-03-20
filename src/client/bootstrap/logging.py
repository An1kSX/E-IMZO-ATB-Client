from __future__ import annotations

import logging


def configure_logging(level: str) -> None:
    normalized_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=normalized_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
