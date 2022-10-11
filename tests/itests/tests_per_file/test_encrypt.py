import json
import base64

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from nacl.public import Box, PrivateKey, PublicKey
from nacl.encoding import Base64Encoder

from jwcrypto.jwt import JWT
from jwcrypto.jwk import JWK


from inge6.config import get_settings
from inge6.constants import Version
from inge6.encrypt import Encrypt

settings = get_settings()


def test_encrypt_data():
    encrypt = Encrypt(
        raw_sign_key=settings.bsn.i6_sign_privkey,
        raw_enc_key=settings.bsn.i4_encrypt_pubkey,
        raw_local_enc_key=settings.bsn.local_symm_key,
    )

    data = {"bsn": "123456789", "authorization_by_proxy": True}

    encrypted_data = encrypt.symm_encrypt(data)
    assert data != encrypted_data
    assert data == encrypt.symm_decrypt(encrypted_data)


def test_pubencrypt_data():
    raw_sign_pubkey = "NGml6EezHnJpy7HygYEglexmmM792EiJbGNvDRkTax0="
    raw_sign_key = "WVC2YjCICx/vjEiHrmqDuY+G3gy78+lwGMxvszPAQYY="
    raw_encrypt_key = "5lyNZZUrta/SFvsVQgA935dvBNfZ18Bg3cj9jO4uO/8="
    raw_encrypt_pubkey = "7uYc+0ZUk7prFMUz2EhDfT8JG0MX8FgVaYCMUXaFN2I="

    encrypt = Encrypt(
        raw_sign_key=raw_sign_key,
        raw_enc_key=raw_encrypt_pubkey,
        raw_local_enc_key=settings.bsn.local_symm_key,
    )

    data = {"bsn": "123456789", "authorization_by_proxy": True}

    sign_pubkey = PublicKey(raw_sign_pubkey, encoder=Base64Encoder)
    enc_privkey = PrivateKey(raw_encrypt_key, encoder=Base64Encoder)

    decrypt_box = Box(enc_privkey, sign_pubkey)
    payload = encrypt.pub_encrypt(data)
    assert (
        json.dumps(data)
        == base64.b64decode(
            decrypt_box.decrypt(payload, encoder=Base64Encoder)
        ).decode()
    )


def test_pubencrypt_data_v1():
    raw_sign_pubkey = "NGml6EezHnJpy7HygYEglexmmM792EiJbGNvDRkTax0="
    raw_sign_key = "WVC2YjCICx/vjEiHrmqDuY+G3gy78+lwGMxvszPAQYY="
    raw_encrypt_key = "5lyNZZUrta/SFvsVQgA935dvBNfZ18Bg3cj9jO4uO/8="
    raw_encrypt_pubkey = "7uYc+0ZUk7prFMUz2EhDfT8JG0MX8FgVaYCMUXaFN2I="

    encrypt = Encrypt(
        raw_sign_key=raw_sign_key,
        raw_enc_key=raw_encrypt_pubkey,
        raw_local_enc_key=settings.bsn.local_symm_key,
    )

    data = "123456789"

    sign_pubkey = PublicKey(raw_sign_pubkey, encoder=Base64Encoder)
    enc_privkey = PrivateKey(raw_encrypt_key, encoder=Base64Encoder)

    decrypt_box = Box(enc_privkey, sign_pubkey)
    payload = encrypt.pub_encrypt(data, version=Version.V1)
    assert decrypt_box.decrypt(payload, encoder=Base64Encoder).decode() == data


def test_recrypt_data_v1():
    raw_sign_pubkey = "NGml6EezHnJpy7HygYEglexmmM792EiJbGNvDRkTax0="
    raw_sign_key = "WVC2YjCICx/vjEiHrmqDuY+G3gy78+lwGMxvszPAQYY="
    raw_encrypt_key = "5lyNZZUrta/SFvsVQgA935dvBNfZ18Bg3cj9jO4uO/8="
    raw_encrypt_pubkey = "7uYc+0ZUk7prFMUz2EhDfT8JG0MX8FgVaYCMUXaFN2I="

    encrypt = Encrypt(
        raw_sign_key=raw_sign_key,
        raw_enc_key=raw_encrypt_pubkey,
        raw_local_enc_key=settings.bsn.local_symm_key,
    )

    data = {"bsn": "123456789", "authorization_by_proxy": True}
    encrypted_data = encrypt.symm_encrypt(data)

    sign_pubkey = PublicKey(raw_sign_pubkey, encoder=Base64Encoder)
    enc_privkey = PrivateKey(raw_encrypt_key, encoder=Base64Encoder)

    decrypt_box = Box(enc_privkey, sign_pubkey)
    payload = encrypt.from_symm_to_pub(encrypted_data, version=Version.V1)

    assert decrypt_box.decrypt(payload, encoder=Base64Encoder).decode() == data["bsn"]


def _create_x25519_privkey(key):
    jwk = JWK()
    jwk._import_pyca_pri_okp(key)  # pylint: disable=protected-access
    return jwk


def test_jwt_encryption():
    raw_sign_pubkey = "k1TOU9vXgtyKCxW6codwEcvRdiaDF2KbBzlwalUIB14="  # Ed25519
    raw_sign_key = "vnb4a91WJFiqBw2kbU4ELwMnOjH/JAPrcLbGg9dRSYg="  # Ed25519
    raw_encrypt_key = "5lyNZZUrta/SFvsVQgA935dvBNfZ18Bg3cj9jO4uO/8="  # X25519
    raw_encrypt_pubkey = "7uYc+0ZUk7prFMUz2EhDfT8JG0MX8FgVaYCMUXaFN2I="  # 25519

    encrypt = Encrypt(
        raw_sign_key=raw_sign_key,
        raw_enc_key=raw_encrypt_pubkey,
        raw_local_enc_key=settings.bsn.local_symm_key,
    )

    data = {"bsn": "123456789", "roleIdentifier": "01"}

    encoded_jwe = encrypt.to_jwe(data)

    sign_public_key_bytes = base64.b64decode(raw_sign_pubkey.encode())
    sign_public_key = Ed25519PublicKey.from_public_bytes(sign_public_key_bytes)

    enc_privkey_bytes = base64.b64decode(raw_encrypt_key.encode())
    enc_privkey = X25519PrivateKey.from_private_bytes(enc_privkey_bytes)

    jwk_enc_privkey = _create_x25519_privkey(enc_privkey)
    jwk_sign_pubkey = JWK.from_pyca(sign_public_key)

    encrypted_jwt = JWT(key=jwk_enc_privkey, jwt=encoded_jwe, expected_type="JWE")
    signed_jwt = JWT(key=jwk_sign_pubkey, jwt=encrypted_jwt.claims)

    claims = json.loads(signed_jwt.claims)
    assert claims["bsn"] == "123456789"
    assert claims["roleIdentifier"] == "01"
