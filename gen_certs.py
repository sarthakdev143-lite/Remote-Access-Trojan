from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DEFAULT_DAYS = 365


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
    )

    eku = (
        [ExtendedKeyUsageOID.SERVER_AUTH]
        if is_server
        else [ExtendedKeyUsageOID.CLIENT_AUTH]
    )
    builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)

    if is_server:
        san = x509.SubjectAlternativeName(
            [
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]
        )
        builder = builder.add_extension(san, critical=False)

    cert = builder.sign(ca_key, hashes.SHA256())
    return key, cert


def make_self_signed_server(*, days: int) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = make_name("localhost")
    san = x509.SubjectAlternativeName(
        [
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]
    )

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days))
        .add_extension(san, critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate certificates for TLS demo")
    parser.add_argument(
        "--mode",
        choices=["selfsigned", "mtls"],
        default="selfsigned",
        help="selfsigned writes server.crt/server.key; mtls writes CA+server+client",
    )
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS)
    parser.add_argument("--out-dir", default=".", help="output directory")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.mode == "selfsigned":
        key, cert = make_self_signed_server(days=args.days)
        write_key(out_dir / "server.key", key)
        write_cert(out_dir / "server.crt", cert)
        print("[+] Wrote server.crt and server.key for localhost / 127.0.0.1")
        return

    ca_key, ca_cert = make_ca(days=args.days)
    server_key, server_cert = make_signed_cert(
        subject_cn="localhost",
        ca_key=ca_key,
        ca_cert=ca_cert,
        days=args.days,
        is_server=True,
    )
    client_key, client_cert = make_signed_cert(
        subject_cn="Local TLS Demo Client",
        ca_key=ca_key,
        ca_cert=ca_cert,
        days=args.days,
        is_server=False,
    )

    write_key(out_dir / "ca.key", ca_key)
    write_cert(out_dir / "ca.crt", ca_cert)
    write_key(out_dir / "server.key", server_key)
    write_cert(out_dir / "server.crt", server_cert)
    write_key(out_dir / "client.key", client_key)
    write_cert(out_dir / "client.crt", client_cert)

    print("[+] Wrote ca.crt/ca.key, server.crt/server.key, client.crt/client.key")
    print("[!] Keep ca.key private. If you commit anything, commit ca.crt only.")


if __name__ == "__main__":
    main()
