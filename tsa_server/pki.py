"""Demo root CA and TSA certificate lifecycle.

On an empty data directory a demo root CA and an RSA time-stamping
certificate are generated. On restart the existing material is reused;
a missing or mismatched private key aborts startup. Private keys are
written with 0600 permissions and are never served over HTTP.
"""

from __future__ import annotations

import datetime as dt
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DAYS = 3650


@dataclass
class PKI:
    root_cert: x509.Certificate
    tsa_cert: x509.Certificate
    tsa_key: rsa.RSAPrivateKey


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def _new_key(bits: int) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def _key_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _generate(data_dir: Path) -> None:
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = _new_key(3072)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Demo TSA Root CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    tsa_key = _new_key(2048)
    tsa_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Demo TSA Signer")])
    tsa_cert = (
        x509.CertificateBuilder()
        .subject_name(tsa_name)
        .issuer_name(ca_cert.subject)
        .public_key(tsa_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(tsa_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    _write_private(data_dir / "ca.key", _key_pem(ca_key))
    _write_private(data_dir / "tsa.key", _key_pem(tsa_key))
    (data_dir / "ca.crt").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    (data_dir / "tsa.crt").write_bytes(tsa_cert.public_bytes(serialization.Encoding.PEM))


def load_or_create(data_dir: Path) -> PKI:
    data_dir.mkdir(parents=True, exist_ok=True)
    names = ["ca.key", "ca.crt", "tsa.key", "tsa.crt"]
    present = [n for n in names if (data_dir / n).exists()]
    if not present:
        _generate(data_dir)
    elif len(present) != len(names):
        missing = sorted(set(names) - set(present))
        raise RuntimeError(f"PKI material incomplete, missing: {', '.join(missing)}")

    root_cert = x509.load_pem_x509_certificate((data_dir / "ca.crt").read_bytes())
    tsa_cert = x509.load_pem_x509_certificate((data_dir / "tsa.crt").read_bytes())
    tsa_key = serialization.load_pem_private_key(
        (data_dir / "tsa.key").read_bytes(), password=None
    )
    if not isinstance(tsa_key, rsa.RSAPrivateKey):
        raise RuntimeError("tsa.key is not an RSA private key")
    if tsa_key.public_key().public_numbers() != tsa_cert.public_key().public_numbers():
        raise RuntimeError("tsa.key does not match tsa.crt; refusing to start")
    return PKI(root_cert=root_cert, tsa_cert=tsa_cert, tsa_key=tsa_key)

