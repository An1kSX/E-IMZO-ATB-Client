from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ProxyCommand:
    plugin: str
    name: str
    arguments: Any = None
    has_arguments: bool = False
