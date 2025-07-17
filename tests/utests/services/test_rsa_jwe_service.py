from app.misc.utils import file_content_raise_if_none
from app.services.encryption.rsa_jwe_service import RSAJweService
from jwcrypto.jwe import JWE
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT

SERVER_RSA_PRIV_KEY_PATH = "secrets/userinfo/jwe_sign.key"
SERVER_RSA_CRT_PATH = "secrets/userinfo/jwe_sign.crt"


def test_to_jwe(test_client, test_client_private_key):
    client_crt_content = file_content_raise_if_none(
        test_client["client_public_key_path"]
    )
    server_key_content = file_content_raise_if_none(SERVER_RSA_CRT_PATH)

    server_key = JWK.from_pem(server_key_content.encode("utf-8"))
    jwe_service = RSAJweService(SERVER_RSA_PRIV_KEY_PATH, SERVER_RSA_CRT_PATH)

    jwe_str = jwe_service.to_jwe({"key": "value"}, client_crt_content)
    jwe = JWE.from_jose_token(jwe_str)
    jwe.decrypt(test_client_private_key)
    jwt = JWT.from_jose_token(jwe.payload.decode("utf-8"))
    jwt.validate(jwe_service.get_pub_jwk())
    jwt.validate(server_key)
    assert jwt.claims == '{"key":"value"}'
