from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import ipaddress
import logging
import os
from pathlib import Path
import platform
import ssl
import subprocess

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from client.bootstrap.config import AppConfig

LOGGER = logging.getLogger(__name__)
_CHECK_INTERVAL_SECONDS = 12 * 60 * 60
_ROOT_CA_VALID_DAYS = 3650
_ROOT_CA_COMMON_NAME = "E-IMZO ATB Client Root CA"
_SERVER_COMMON_NAME = "127.0.0.1"
_SERVER_ORGANIZATION_NAME = "E-IMZO ATB Client"


@dataclass(frozen=True, slots=True)
class LocalCertificate:
    cert_path: Path
    key_path: Path
    renewed: bool
    managed: bool = True
    ca_cert_path: Path | None = None


def resolve_server_certificate(config: AppConfig) -> LocalCertificate:
    if config.use_managed_server_certificate():
        return ensure_localhost_certificate(config)

    if config.ws_server_cert_path is None or config.ws_server_key_path is None:
        raise RuntimeError("Custom server certificate is not fully configured.")

    return LocalCertificate(
        cert_path=config.ws_server_cert_path,
        key_path=config.ws_server_key_path,
        renewed=False,
        managed=False,
        ca_cert_path=None,
    )


def ensure_localhost_certificate(config: AppConfig) -> LocalCertificate:
    cert_dir = config.runtime_dir / "certs"
    cert_dir.mkdir(parents=True, exist_ok=True)

    ca_cert_path = cert_dir / "root-ca.pem"
    ca_key_path = cert_dir / "root-ca-key.pem"
    cert_path = cert_dir / "127.0.0.1.pem"
    key_path = cert_dir / "127.0.0.1-key.pem"

    ca_renewed = _needs_renewal(
        cert_path=ca_cert_path,
        key_path=ca_key_path,
        renew_before_days=config.local_cert_renew_before_days,
    )
    if ca_renewed:
        _generate_root_certificate_authority(
            cert_path=ca_cert_path,
            key_path=ca_key_path,
            valid_days=_ROOT_CA_VALID_DAYS,
        )

    ca_certificate = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
    ca_private_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)

    server_renewed = ca_renewed or _needs_server_certificate_renewal(
        cert_path=cert_path,
        key_path=key_path,
        renew_before_days=config.local_cert_renew_before_days,
        ca_certificate=ca_certificate,
    )
    if server_renewed:
        _generate_localhost_certificate(
            cert_path=cert_path,
            key_path=key_path,
            ca_certificate=ca_certificate,
            ca_private_key=ca_private_key,
            valid_days=config.local_cert_valid_days,
        )

    if config.local_cert_install_to_windows_root_store:
        _ensure_windows_root_certificate_is_trusted(ca_cert_path)

    return LocalCertificate(
        cert_path=cert_path,
        key_path=key_path,
        renewed=ca_renewed or server_renewed,
        managed=True,
        ca_cert_path=ca_cert_path,
    )


def build_client_ssl_context(cert_path: Path) -> ssl.SSLContext:
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


def _needs_server_certificate_renewal(
    *,
    cert_path: Path,
    key_path: Path,
    renew_before_days: int,
    ca_certificate: x509.Certificate,
) -> bool:
    if _needs_renewal(
        cert_path=cert_path,
        key_path=key_path,
        renew_before_days=renew_before_days,
    ):
        return True

    certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
    return certificate.issuer != ca_certificate.subject


def _generate_root_certificate_authority(
    *,
    cert_path: Path,
    key_path: Path,
    valid_days: int,
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, _ROOT_CA_COMMON_NAME),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, _SERVER_ORGANIZATION_NAME),
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
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
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


def _generate_localhost_certificate(
    *,
    cert_path: Path,
    key_path: Path,
    ca_certificate: x509.Certificate,
    ca_private_key: rsa.RSAPrivateKey,
    valid_days: int,
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, _SERVER_COMMON_NAME),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, _SERVER_ORGANIZATION_NAME),
        ]
    )
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)
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
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
            critical=False,
        )
        .sign(ca_private_key, hashes.SHA256())
    )

    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def _ensure_windows_root_certificate_is_trusted(cert_path: Path) -> None:
    if platform.system() != "Windows":
        return

    if _is_certificate_trusted_in_windows_root_store(cert_path):
        return

    certutil_path = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "certutil.exe"
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    try:
        completed = subprocess.run(
            [str(certutil_path), "-user", "-f", "-addstore", "Root", str(cert_path)],
            capture_output=True,
            check=True,
            creationflags=creation_flags,
            text=True,
        )
    except FileNotFoundError as error:
        raise RuntimeError("Windows certutil.exe was not found, so the local root CA could not be trusted.") from error
    except subprocess.CalledProcessError as error:
        output = (error.stderr or error.stdout or "").strip()
        raise RuntimeError(
            "Failed to install the local root CA into the Windows current-user trust store."
            + (f" certutil output: {output}" if output else "")
        ) from error

    output = (completed.stdout or completed.stderr or "").strip()
    LOGGER.info("Installed local root CA into Windows current-user trust store. %s", output)


def _is_certificate_trusted_in_windows_root_store(cert_path: Path) -> bool:
    expected_der = x509.load_pem_x509_certificate(cert_path.read_bytes()).public_bytes(
        serialization.Encoding.DER
    )

    for certificate_bytes, encoding, _trust in ssl.enum_certificates("ROOT"):
        if encoding == "x509_asn" and certificate_bytes == expected_der:
            return True

    return False
