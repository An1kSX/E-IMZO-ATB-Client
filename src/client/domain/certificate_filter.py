from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from client.domain.key_identity_store import KeyIdentity, extract_key_identity

_DS_KEY_NAME_PATTERN = re.compile(r"^DS(?P<digits>\d+)$", re.IGNORECASE)
_TRAILING_SEQUENCE_WIDTH = 4


@dataclass(frozen=True, slots=True)
class CertificateFilterResult:
    certificates: list[Any]
    removed_count: int


@dataclass(frozen=True, slots=True)
class _CertificateVersion:
    group_key: str
    sequence_number: int


def filter_duplicate_certificate_keys(certificates: Any) -> CertificateFilterResult | None:
    if not isinstance(certificates, list):
        return None

    selected_indexes_by_group: dict[str, tuple[int, int]] = {}
    for index, certificate in enumerate(certificates):
        version = _extract_certificate_version(certificate)
        if version is None:
            continue

        selected = selected_indexes_by_group.get(version.group_key)
        if selected is None or version.sequence_number > selected[1]:
            selected_indexes_by_group[version.group_key] = (index, version.sequence_number)

    if not selected_indexes_by_group:
        return CertificateFilterResult(certificates=list(certificates), removed_count=0)

    selected_group_indexes = {
        selected_index
        for selected_index, _sequence_number in selected_indexes_by_group.values()
    }
    grouped_indexes = set()
    for index, certificate in enumerate(certificates):
        if _extract_certificate_version(certificate) is not None:
            grouped_indexes.add(index)

    filtered_certificates = [
        certificate
        for index, certificate in enumerate(certificates)
        if index not in grouped_indexes or index in selected_group_indexes
    ]
    return CertificateFilterResult(
        certificates=filtered_certificates,
        removed_count=len(certificates) - len(filtered_certificates),
    )


def _extract_certificate_version(certificate: Any) -> _CertificateVersion | None:
    if not isinstance(certificate, dict):
        return None

    name = _normalize_text(certificate.get("name"))
    if name is None:
        return None

    ds_name_match = _DS_KEY_NAME_PATTERN.match(name)
    if ds_name_match is None:
        return None

    digits = ds_name_match.group("digits")
    identity = _extract_certificate_identity(certificate=certificate, name=name)
    parsed_with_identity = _parse_ds_name_with_identity(digits=digits, identity=identity)
    if parsed_with_identity is not None:
        return parsed_with_identity

    if len(digits) <= _TRAILING_SEQUENCE_WIDTH:
        return None

    stable_digits = digits[:-_TRAILING_SEQUENCE_WIDTH]
    sequence_digits = digits[-_TRAILING_SEQUENCE_WIDTH:]
    return _CertificateVersion(
        group_key=f"DS{stable_digits}",
        sequence_number=int(sequence_digits),
    )


def _extract_certificate_identity(*, certificate: dict[Any, Any], name: str) -> KeyIdentity | None:
    alias = _normalize_text(certificate.get("alias"))
    subject = _normalize_text(certificate.get("subject"))
    key_subject = _normalize_text(certificate.get("key_subject")) or subject or alias
    return extract_key_identity(key_alias=name, key_subject=key_subject)


def _parse_ds_name_with_identity(*, digits: str, identity: KeyIdentity | None) -> _CertificateVersion | None:
    if identity is None:
        return None

    for identity_value in (identity.pinfl, identity.inn):
        if identity_value is None:
            continue
        if not digits.startswith(identity_value):
            continue

        sequence_digits = digits[len(identity_value) :]
        if not sequence_digits or not sequence_digits.isdigit():
            continue

        return _CertificateVersion(
            group_key=f"DS{identity_value}",
            sequence_number=int(sequence_digits),
        )

    return None


def _normalize_text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None

    normalized = value.strip()
    return normalized or None
