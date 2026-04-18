# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PrintForge Contributors

"""Generate seed corpus files for the certificate parser fuzz targets.

Run this script once before the first fuzzing session:

    python3 crates/pf-auth/fuzz/generate_corpus.py

Requires: pip install cryptography
"""

import os

CORPUS_DER_DIR = os.path.join(os.path.dirname(__file__), "corpus", "certificate_parser")
CORPUS_PEM_DIR = os.path.join(os.path.dirname(__file__), "corpus", "pem_parser")
os.makedirs(CORPUS_DER_DIR, exist_ok=True)
os.makedirs(CORPUS_PEM_DIR, exist_ok=True)


def generate_self_signed_der() -> bytes:
    """Generate a self-signed test certificate in DER format."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "DOE.JOHN.Q.1234567890"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Unit, Test Base AFB"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def generate_self_signed_pem() -> bytes:
    """Generate a self-signed test certificate in PEM format."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "DOE.JANE.A.0987654321"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Unit, Test Base AFB"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def main() -> None:
    try:
        der_data = generate_self_signed_der()
        pem_data = generate_self_signed_pem()

        der_path = os.path.join(CORPUS_DER_DIR, "self_signed_test")
        with open(der_path, "wb") as f:
            f.write(der_data)
        print(f"  wrote {der_path} ({len(der_data)} bytes)")

        pem_path = os.path.join(CORPUS_PEM_DIR, "self_signed_test")
        with open(pem_path, "wb") as f:
            f.write(pem_data)
        print(f"  wrote {pem_path} ({len(pem_data)} bytes)")

        print("Seed corpus ready.")
    except ImportError:
        print("WARNING: 'cryptography' package not installed.")
        print("Install it with: pip install cryptography")
        print("Then re-run this script to generate seed corpus files.")
        print("Fuzzing will still work without seeds, but coverage ramp-up will be slower.")


if __name__ == "__main__":
    main()
