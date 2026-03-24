from __future__ import annotations

import json

from client.domain.commands import ProxyCommand


def parse_proxy_command(raw_message: str | bytes) -> ProxyCommand:
    if isinstance(raw_message, bytes):
        raw_message = raw_message.decode("utf-8")

    payload = json.loads(raw_message)
    return ProxyCommand(
        plugin=payload.get("plugin"),
        name=payload["name"],
        arguments=payload.get("arguments"),
        has_arguments=bool(payload.get("arguments")),
    )
