from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import ipaddress
import logging
from pathlib import Path
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from client.bootstrap.config import AppConfig

LOGGER = logging.getLogger(__name__)
_CHECK_INTERVAL_SECONDS = 12 * 60 * 60


@dataclass(frozen=True, slots=True)
class LocalCertificate:
    cert_path: Path
    key_path: Path
    renewed: bool


def ensure_localhost_certificate(config: AppConfig) -> LocalCertificate:
    cert_dir = config.runtime_dir / "certs"
    cert_dir.mkdir(parents=True, exist_ok=True)

    cert_path = cert_dir / "127.0.0.1.pem"
    key_path = cert_dir / "127.0.0.1-key.pem"
    renewed = _needs_renewal(
        cert_path=cert_path,
        key_path=key_path,
        renew_before_days=config.local_cert_renew_before_days,
    )

    if renewed:
        _generate_localhost_certificate(
            cert_path=cert_path,
            key_path=key_path,
            valid_days=config.local_cert_valid_days,
        )

    return LocalCertificate(cert_path=cert_path, key_path=key_path, renewed=renewed)


def build_local_api_ssl_context(cert_path: Path) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=str(cert_path))


def build_websocket_server_ssl_context(*, cert_path: Path, key_path: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return context


async def maintain_localhost_certificate(
    config: AppConfig,
    rotation_event: asyncio.Event | None = None,
) -> None:
    while True:
        await asyncio.sleep(_CHECK_INTERVAL_SECONDS)
        certificate = ensure_localhost_certificate(config)
        if certificate.renewed:
            LOGGER.info("Local certificate for 127.0.0.1 was renewed: %s", certificate.cert_path)
            if rotation_event is not None:
                rotation_event.set()


def _needs_renewal(
    *,
    cert_path: Path,
    key_path: Path,
    renew_before_days: int,
) -> bool:
    if not cert_path.exists() or not key_path.exists():
        return True

    try:
        certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
    except Exception:
        return True

    expires_at = certificate.not_valid_after.replace(tzinfo=timezone.utc)
    renew_after = datetime.now(timezone.utc) + timedelta(days=renew_before_days)
    return expires_at <= renew_after


def _generate_localhost_certificate(
    *,
    cert_path: Path,
    key_path: Path,
    valid_days: int,
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "E-IMZO ATB Client"),
        ]
    )
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=valid_days))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )

    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
