from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ProxyCommand:
    name: str
    plugin: str | None = None
    arguments: Any = None
    has_arguments: bool = False
