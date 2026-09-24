"""Persistent installation ID, stored with the application's runtime settings."""
import logging
from pathlib import Path
from uuid import UUID, uuid4


def installation_id(runtime_dir: Path) -> str | None:
    path = runtime_dir / "audit-client-id"
    try:
        runtime_dir.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            try:
                with path.open("x", encoding="ascii") as stream:
                    stream.write(str(uuid4()))
            except FileExistsError:
                pass
        return str(UUID(path.read_text(encoding="ascii").strip()))
    except (OSError, ValueError):
        logging.getLogger(__name__).warning("Cannot read or persist audit installation ID")
        return None
