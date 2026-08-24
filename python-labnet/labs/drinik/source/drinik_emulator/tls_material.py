from __future__ import annotations

import datetime as dt
import ipaddress
import ssl
from pathlib import Path


def ensure_self_signed_cert(
    cert_dir: Path,
    firebase_ip: str = "172.217.114.4",
    mtalk_ip: str = "108.177.15.188",
) -> tuple[Path, Path]:
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_path = cert_dir / "firebase_gateway.crt"
    key_path = cert_dir / "firebase_gateway.key"
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except Exception as exc:  # pragma: no cover - depends on local environment
        raise RuntimeError(
            "The TLS emulator needs 'cryptography' to generate a self-signed certificate. "
            "Install it or provide cert/key files manually."
        ) from exc

    expected_dns_names = {
        "firebaseinstallations.googleapis.com",
        "android.apis.google.com",
        "fcm.googleapis.com",
        "mtalk.google.com",
        "mtalk4.google.com",
        "alt1-mtalk.google.com",
    }
    expected_ip_names = {
        ipaddress.ip_address(firebase_ip),
        ipaddress.ip_address(mtalk_ip),
    }

    if cert_path.exists() and key_path.exists():
        try:
            existing_cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            existing_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
            san = existing_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            if (
                set(san.get_values_for_type(x509.DNSName)) == expected_dns_names
                and set(san.get_values_for_type(x509.IPAddress)) == expected_ip_names
                and existing_cert.public_key().public_numbers()
                == existing_key.public_key().public_numbers()
            ):
                return cert_path, key_path
        except (OSError, ValueError, TypeError, x509.ExtensionNotFound):
            pass

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Drinik Traffic Lab"),
            x509.NameAttribute(NameOID.COMMON_NAME, "firebaseinstallations.googleapis.com"),
        ]
    )
    alt_names = [
        x509.DNSName("firebaseinstallations.googleapis.com"),
        x509.DNSName("android.apis.google.com"),
        x509.DNSName("fcm.googleapis.com"),
        x509.DNSName("mtalk.google.com"),
        x509.DNSName("mtalk4.google.com"),
        x509.DNSName("alt1-mtalk.google.com"),
        x509.IPAddress(ipaddress.ip_address(firebase_ip)),
        x509.IPAddress(ipaddress.ip_address(mtalk_ip)),
    ]
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.UTC) - dt.timedelta(days=1))
        .not_valid_after(dt.datetime.now(dt.UTC) + dt.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
        .sign(key, hashes.SHA256())
    )

    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def server_context(cert_path: Path, key_path: Path, keylog_path: Path | None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    if keylog_path is not None:
        keylog_path.parent.mkdir(parents=True, exist_ok=True)
        ctx.keylog_filename = str(keylog_path)
    return ctx


def client_context(keylog_path: Path | None) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if keylog_path is not None:
        keylog_path.parent.mkdir(parents=True, exist_ok=True)
        ctx.keylog_filename = str(keylog_path)
    return ctx


def close_tls_gracefully(sock: ssl.SSLSocket, timeout: float = 2.0) -> bool:
    """Exchange TLS close_notify before closing the underlying TCP socket."""
    try:
        sock.settimeout(timeout)
        raw_sock = sock.unwrap()
    except (OSError, ssl.SSLError):
        sock.close()
        return False
    raw_sock.close()
    return True
