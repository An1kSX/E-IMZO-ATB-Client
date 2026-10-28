from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

_CertificateGroup = tuple[str | None, str | None, str | None, str | None]


@dataclass(frozen=True, slots=True)
class CertificateFilterResult:
    certificates: list[Any]
    removed_count: int


def filter_duplicate_certificate_keys(certificates: Any) -> CertificateFilterResult | None:
    if not isinstance(certificates, list):
        return None

    selected_by_group: dict[_CertificateGroup, tuple[int, float]] = {}
    comparable_indexes: set[int] = set()
    for index, certificate in enumerate(certificates):
        if not isinstance(certificate, dict):
            continue
        attributes = _certificate_attributes(certificate)
        group = _certificate_group(attributes)
        expires_at = _expiration_timestamp(attributes)
        # Unknown identities or dates must not cause a potentially usable key to disappear.
        if group is None or expires_at is None:
            continue
        comparable_indexes.add(index)
        selected = selected_by_group.get(group)
        if selected is None or expires_at > selected[1]:
            selected_by_group[group] = (index, expires_at)

    selected_indexes = {index for index, _expires_at in selected_by_group.values()}
    filtered = [
        certificate
        for index, certificate in enumerate(certificates)
        if index not in comparable_indexes or index in selected_indexes
    ]
    return CertificateFilterResult(certificates=filtered, removed_count=len(certificates) - len(filtered))


def _certificate_attributes(certificate: dict[Any, Any]) -> dict[str, str]:
    attributes: dict[str, str] = {}
    for field in ("alias", "subject", "key_subject"):
        subject = certificate.get(field)
        if not isinstance(subject, str):
            continue
        for part in subject.split(","):
            key, separator, value = part.partition("=")
            if separator and value.strip():
                attributes[key.strip().casefold()] = value.strip()
    # Also accept explicit fields from certificate-list responses.
    for key, value in certificate.items():
        if isinstance(key, str) and isinstance(value, str) and value.strip():
            attributes[key.casefold()] = value.strip()
    return attributes


def _certificate_group(attributes: dict[str, str]) -> _CertificateGroup | None:
    inn = _identity_value(attributes, ("1.2.860.3.16.1.1", "tin", "inn", "uid"), length=9)
    pinfl = _identity_value(attributes, ("1.2.860.3.16.1.2", "pinfl", "uid"), length=14)
    if inn is None and pinfl is None:
        return None
    # A company can have several signers, and one signer can represent several companies.
    owner = attributes.get("cn") if pinfl is None else None
    organization = attributes.get("o") if inn is None else None
    if pinfl is None and owner is None:
        return None
    return (
        inn,
        pinfl,
        " ".join(owner.casefold().split()) if owner else None,
        " ".join(organization.casefold().split()) if organization else None,
    )


def _identity_value(attributes: dict[str, str], keys: tuple[str, ...], *, length: int) -> str | None:
    for key in keys:
        value = attributes.get(key)
        if value is not None and len(value) == length and value.isascii() and value.isdigit():
            return value
    return None


def _expiration_timestamp(attributes: dict[str, str]) -> float | None:
    for key in ("validto", "valid_to"):
        value = attributes.get(key)
        if value is None:
            continue
        try:
            expiration = datetime.fromisoformat(value)
        except ValueError:
            try:
                expiration = datetime.strptime(value, "%Y.%m.%d %H:%M:%S")
            except ValueError:
                continue
        try:
            # E-IMZO dates without an offset use the client's local timezone.
            return expiration.timestamp()
        except (ValueError, OverflowError, OSError):
            continue
    return None
