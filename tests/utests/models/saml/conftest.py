import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


@pytest.fixture
def priv_key_path(tmp_path):
    d = tmp_path / "secrets"
    d.mkdir()
    p = d / "priv_key.pem"
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    p.write_text(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
    )

    yield p.absolute()
