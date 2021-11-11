from inge6.config import get_settings
from inge6.encrypt import Encrypt

settings = get_settings()
encrypt = Encrypt(
    raw_sign_key=settings.bsn.sign_key,
    raw_sign_pubkey=settings.bsn.sign_pubkey,
    raw_enc_key=settings.bsn.encrypt_key,
    raw_local_enc_key=settings.bsn.local_symm_key,
)

def test_encrypt_data():
    data = {
        'bsn': '123456789',
        'authorization_by_proxy': True
    }

    encrypted_data = encrypt.symm_encrypt(data)
    assert data != encrypted_data
    assert data == encrypt.symm_decrypt(encrypted_data)

def test_jwt_encryption():
    data = {
        'bsn': '123456789',
        'authorization_by_proxy': True
    }

    print(encrypt.to_jwe(data))