from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DEFAULT_DAYS = 365
DEFAULT_SAN_DEFAULTS = ["localhost", "127.0.0.1"]


def write_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def write_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def make_name(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Maharashtra"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Mumbai"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Local TLS Demo"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _build_san_values(server_cn: str, extras: Iterable[str]) -> list[str]:
    seen: list[str] = []

    def add(value: str) -> None:
        value = value.strip()
        if value and value not in seen:
            seen.append(value)

    add(server_cn)
    for default in DEFAULT_SAN_DEFAULTS:
        add(default)
    for extra in extras:
        add(extra)
    return seen


def _san_general_names(values: Iterable[str]) -> list[x509.GeneralName]:
    names: list[x509.GeneralName] = []
    for value in values:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            names.append(x509.DNSName(value))
        else:
            names.append(x509.IPAddress(ip))
    return names


def make_ca(*, days: int) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = make_name("Local TLS Demo CA")
    now = datetime.now(timezone.utc)

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days))
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
        .sign(ca_key, hashes.SHA256())
    )
    return ca_key, ca_cert


def make_signed_cert(
    *,
    subject_cn: str,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    days: int,
    is_server: bool,
    san_entries: list[x509.GeneralName] | None = None,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = make_name(subject_cn)
    now = datetime.now(timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH] if is_server else [ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
    )

    if san_entries:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
    elif is_server:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )

    cert = builder.sign(ca_key, hashes.SHA256())
    return key, cert


def main() -> None:
    out_dir = Path(".")
    out_dir.mkdir(parents=True, exist_ok=True)

    san_values = _build_san_values("localhost", [])
    san_general_names = _san_general_names(san_values)

    ca_key, ca_cert = make_ca(days=DEFAULT_DAYS)
    server_key, server_cert = make_signed_cert(
        subject_cn="localhost",
        ca_key=ca_key,
        ca_cert=ca_cert,
        days=DEFAULT_DAYS,
        is_server=True,
        san_entries=san_general_names,
    )
    client_key, client_cert = make_signed_cert(
        subject_cn="Local TLS Demo Client",
        ca_key=ca_key,
        ca_cert=ca_cert,
        days=DEFAULT_DAYS,
        is_server=False,
    )

    write_key(out_dir / "ca.key", ca_key)
    write_cert(out_dir / "ca.crt", ca_cert)
    write_key(out_dir / "server.key", server_key)
    write_cert(out_dir / "server.crt", server_cert)
    write_key(out_dir / "client.key", client_key)
    write_cert(out_dir / "client.crt", client_cert)

    print("[+] Wrote ca.crt/ca.key, server.crt/server.key, client.crt/client.key")
    print("[!] Keep ca.key private. Commit ca.crt only.")


if __name__ == "__main__":
    main()
