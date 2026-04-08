from __future__ import annotations

from collections import OrderedDict
from pathlib import Path
import re
from typing import TypeAlias

INN_LENGTH = 9
PINFL_LENGTH = 14
PINFL_KEY_NAME_LENGTH = 20
MAX_STORED_KEY_IDS = 1000
_KeyScope: TypeAlias = tuple[str | None, str]
_LEADING_DIGITS_PATTERN = re.compile(r"^(\d+)")


class KeyIdentityStore:
    def __init__(self, *, max_entries: int = MAX_STORED_KEY_IDS) -> None:
        self._max_entries = max_entries
        self._identities_by_scoped_key_id: OrderedDict[_KeyScope, str] = OrderedDict()
        self._scoped_key_ids_by_identity: dict[_KeyScope, _KeyScope] = {}

    def remember(self, *, key_id: str, key_name: str, origin: str | None = None) -> str | None:
        identity = extract_identity_from_key_name(key_name)
        if identity is None:
            return None

        scoped_key_id = (origin, key_id)
        scoped_identity = (origin, identity)
        existing_scoped_key_id = self._scoped_key_ids_by_identity.get(scoped_identity)
        if existing_scoped_key_id is not None and existing_scoped_key_id != scoped_key_id:
            self._identities_by_scoped_key_id.pop(existing_scoped_key_id, None)

        self._identities_by_scoped_key_id.pop(scoped_key_id, None)
        self._identities_by_scoped_key_id[scoped_key_id] = identity
        self._scoped_key_ids_by_identity[scoped_identity] = scoped_key_id
        self._trim_to_capacity()
        return identity

    def get(self, key_id: str, *, origin: str | None = None) -> str | None:
        return self._identities_by_scoped_key_id.get((origin, key_id))

    def _trim_to_capacity(self) -> None:
        while len(self._identities_by_scoped_key_id) > self._max_entries:
            oldest_scoped_key_id, oldest_identity = self._identities_by_scoped_key_id.popitem(last=False)
            scoped_identity = (oldest_scoped_key_id[0], oldest_identity)
            if self._scoped_key_ids_by_identity.get(scoped_identity) == oldest_scoped_key_id:
                self._scoped_key_ids_by_identity.pop(scoped_identity, None)


def extract_identity_from_key_name(key_name: str) -> str | None:
    normalized_name = Path(str(key_name)).stem.strip()
    if not normalized_name:
        return None

    upper_name = normalized_name.upper()
    if upper_name.startswith("DS"):
        normalized_name = normalized_name[2:].strip()

    leading_digits_match = _LEADING_DIGITS_PATTERN.match(normalized_name)
    if leading_digits_match is None:
        return None

    normalized_name = leading_digits_match.group(1)

    if len(normalized_name) < INN_LENGTH:
        return None

    if len(upper_name) >= PINFL_KEY_NAME_LENGTH and len(normalized_name) >= PINFL_LENGTH:
        return normalized_name[:PINFL_LENGTH]

    return normalized_name[:INN_LENGTH]
