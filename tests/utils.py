from datetime import datetime, timezone, timedelta
from typing import Tuple

from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from jwcrypto.jwk import JWK

from app.misc.utils import load_certificate_with_jwk, kid_from_certificate
from app.models.certificate_with_jwk import CertificateWithJWK


def make_test_certificate() -> Tuple[CertificateWithJWK, JWK]:
    key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "NL"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Test State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Test City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "max.example.com"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=10))
        .sign(key, algorithm=hashes.SHA256(), backend=default_backend())
    )

    private_jwk = JWK.from_pyca(key)
    private_jwk.kid = kid_from_certificate(cert)

    cert_with_jwk = load_certificate_with_jwk(cert)
    return cert_with_jwk, private_jwk


def make_test_rsa_key() -> JWK:
    key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    return JWK.from_pyca(key)
