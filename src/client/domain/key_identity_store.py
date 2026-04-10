from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
import re
from typing import TypeAlias

INN_LENGTH = 9
PINFL_LENGTH = 14
MAX_STORED_KEY_IDS = 1000
_KeyScope: TypeAlias = tuple[str | None, str]
_LEADING_DIGITS_PATTERN = re.compile(r"^(\d+)")
_PINFL_OID = "1.2.860.3.16.1.2"
_INN_OID = "1.2.860.3.16.1.1"
_UID_ATTRIBUTE = "uid"


@dataclass(frozen=True, slots=True)
class KeyIdentity:
    inn: str | None = None
    pinfl: str | None = None

    def argument_values(self) -> list[str]:
        values: list[str] = []
        if self.pinfl:
            values.append(self.pinfl)
        if self.inn:
            values.append(self.inn)
        return values

    def first_available(self) -> str | None:
        return self.pinfl or self.inn

    def has_any(self) -> bool:
        return self.inn is not None or self.pinfl is not None


class KeyIdentityStore:
    def __init__(self, *, max_entries: int = MAX_STORED_KEY_IDS) -> None:
        self._max_entries = max_entries
        self._identities_by_scoped_key_id: OrderedDict[_KeyScope, KeyIdentity] = OrderedDict()

    def remember(
        self,
        *,
        key_id: str,
        key_alias: str | None = None,
        key_subject: str | None = None,
        key_name: str | None = None,
        origin: str | None = None,
    ) -> KeyIdentity | None:
        if key_alias is None:
            key_alias = key_name

        identity = extract_key_identity(key_alias=key_alias, key_subject=key_subject)
        if identity is None:
            return None

        scoped_key_id = (origin, key_id)
        self._identities_by_scoped_key_id.pop(scoped_key_id, None)
        self._identities_by_scoped_key_id[scoped_key_id] = identity
        self._trim_to_capacity()
        return identity

    def get(self, key_id: str, *, origin: str | None = None) -> str | None:
        identity = self.get_key_identity(key_id, origin=origin)
        if identity is None:
            return None
        return identity.first_available()

    def get_key_identity(self, key_id: str, *, origin: str | None = None) -> KeyIdentity | None:
        identity = self._identities_by_scoped_key_id.get((origin, key_id))
        if identity is not None:
            return identity

        for (stored_origin, stored_key_id), stored_identity in reversed(self._identities_by_scoped_key_id.items()):
            if stored_key_id != key_id:
                continue
            if stored_origin == origin:
                continue
            return stored_identity

        return None

    def _trim_to_capacity(self) -> None:
        while len(self._identities_by_scoped_key_id) > self._max_entries:
            self._identities_by_scoped_key_id.popitem(last=False)


def extract_key_identity(*, key_alias: str | None, key_subject: str | None) -> KeyIdentity | None:
    subject_identity = _extract_key_identity_from_subject(key_subject)
    alias_identity = _extract_key_identity_from_key_alias(key_alias)

    inn = subject_identity.inn if subject_identity and subject_identity.inn else None
    pinfl = subject_identity.pinfl if subject_identity and subject_identity.pinfl else None
    if inn is None and alias_identity is not None:
        inn = alias_identity.inn
    if pinfl is None and alias_identity is not None:
        pinfl = alias_identity.pinfl

    identity = KeyIdentity(inn=inn, pinfl=pinfl)
    if identity.has_any():
        return identity
    return None


def _extract_key_identity_from_subject(key_subject: str | None) -> KeyIdentity | None:
    if not isinstance(key_subject, str) or not key_subject.strip():
        return None

    attributes = _parse_subject_attributes(key_subject)
    if not attributes:
        return None

    pinfl = _normalize_identity_value(attributes.get(_PINFL_OID), expected_length=PINFL_LENGTH)
    inn = _normalize_identity_value(attributes.get(_INN_OID), expected_length=INN_LENGTH)
    if inn is None:
        inn = _normalize_identity_value(attributes.get(_UID_ATTRIBUTE), expected_length=INN_LENGTH)

    identity = KeyIdentity(inn=inn, pinfl=pinfl)
    if identity.has_any():
        return identity
    return None


def _parse_subject_attributes(raw_subject: str) -> dict[str, str]:
    attributes: dict[str, str] = {}
    for raw_part in raw_subject.split(","):
        part = raw_part.strip()
        if not part or "=" not in part:
            continue

        key, value = part.split("=", 1)
        normalized_key = key.strip().casefold()
        normalized_value = value.strip()
        if normalized_key and normalized_value:
            attributes[normalized_key] = normalized_value
    return attributes


def _extract_key_identity_from_key_alias(key_alias: str | None) -> KeyIdentity | None:
    if not isinstance(key_alias, str) or not key_alias.strip():
        return None

    normalized_alias = Path(key_alias).stem.strip()
    if not normalized_alias:
        return None

    upper_alias = normalized_alias.upper()
    if upper_alias.startswith("DS"):
        normalized_alias = normalized_alias[2:].strip()

    leading_digits_match = _LEADING_DIGITS_PATTERN.match(normalized_alias)
    if leading_digits_match is None:
        return None

    digits = leading_digits_match.group(1)
    # If alias contains a PINFL-length prefix, treat it as PINFL-only.
    # Do not derive INN from the same digits to avoid sending synthetic INN values.
    pinfl = _normalize_identity_value(digits, expected_length=PINFL_LENGTH)
    inn: str | None = None
    if pinfl is None:
        inn = _normalize_identity_value(digits, expected_length=INN_LENGTH)

    identity = KeyIdentity(inn=inn, pinfl=pinfl)
    if identity.has_any():
        return identity
    return None


def _normalize_identity_value(value: str | None, *, expected_length: int) -> str | None:
    if not isinstance(value, str):
        return None

    digits = "".join(ch for ch in value if ch.isdigit())
    if len(digits) < expected_length:
        return None

    return digits[:expected_length]


def extract_identity_from_key_name(key_name: str) -> str | None:
    identity = _extract_key_identity_from_key_alias(key_name)
    if identity is None:
        return None
    return identity.pinfl or identity.inn
