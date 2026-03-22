from datetime import datetime, timedelta, timezone
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CERT_FILE = "server.crt"
KEY_FILE = "server.key"


def main() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Maharashtra"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Mumbai"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Local TLS Demo"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ]
    )

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
        .not_valid_after(now + timedelta(days=365))
        .add_extension(san, critical=False)
        .sign(key, hashes.SHA256())
    )

    with open(KEY_FILE, "wb") as key_file:
        key_file.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(CERT_FILE, "wb") as cert_file:
        cert_file.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] Wrote {CERT_FILE} and {KEY_FILE} for localhost / 127.0.0.1")


if __name__ == "__main__":
    main()
