from __future__ import annotations

from collections import OrderedDict
from pathlib import Path

INN_LENGTH = 9
PINFL_LENGTH = 14
PINFL_KEY_NAME_LENGTH = 20
MAX_STORED_KEY_IDS = 100


class KeyIdentityStore:
    def __init__(self, *, max_entries: int = MAX_STORED_KEY_IDS) -> None:
        self._max_entries = max_entries
        self._identities_by_key_id: OrderedDict[str, str] = OrderedDict()
        self._key_ids_by_identity: dict[str, str] = {}

    def remember(self, *, key_id: str, key_name: str) -> str | None:
        identity = extract_identity_from_key_name(key_name)
        if identity is None:
            return None

        existing_key_id = self._key_ids_by_identity.get(identity)
        if existing_key_id is not None and existing_key_id != key_id:
            self._identities_by_key_id.pop(existing_key_id, None)

        self._identities_by_key_id.pop(key_id, None)
        self._identities_by_key_id[key_id] = identity
        self._key_ids_by_identity[identity] = key_id
        self._trim_to_capacity()
        return identity

    def get(self, key_id: str) -> str | None:
        return self._identities_by_key_id.get(key_id)

    def _trim_to_capacity(self) -> None:
        while len(self._identities_by_key_id) > self._max_entries:
            oldest_key_id, oldest_identity = self._identities_by_key_id.popitem(last=False)
            if self._key_ids_by_identity.get(oldest_identity) == oldest_key_id:
                self._key_ids_by_identity.pop(oldest_identity, None)


def extract_identity_from_key_name(key_name: str) -> str | None:
    normalized_name = Path(str(key_name)).stem.strip()
    if not normalized_name:
        return None

    upper_name = normalized_name.upper()
    if upper_name.startswith("DS"):
        normalized_name = normalized_name[2:]

    if not normalized_name.isdigit():
        return None

    if len(normalized_name) < INN_LENGTH:
        return None

    if len(upper_name) >= PINFL_KEY_NAME_LENGTH and len(normalized_name) >= PINFL_LENGTH:
        return normalized_name[:PINFL_LENGTH]

    return normalized_name[:INN_LENGTH]
