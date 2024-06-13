from app.misc.utils import file_content_raise_if_none
from app.services.encryption.rsa_jwe_service import RSAJweService
from jwcrypto.jwe import JWE
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT

SERVER_RSA_PRIV_KEY_PATH = "secrets/userinfo/jwe_sign.key"
SERVER_RSA_CRT_PATH = "secrets/userinfo/jwe_sign.crt"
CLIENT_RSA_PRIV_KEY_PATH = "secrets/clients/test_client/test_client.key"
CLIENT_RSA_CRT_PATH = "secrets/clients/test_client/test_client.crt"


def test_to_jwe():
    client_crt_content = file_content_raise_if_none(CLIENT_RSA_CRT_PATH)
    client_key_content = file_content_raise_if_none(CLIENT_RSA_PRIV_KEY_PATH)
    server_key_content = file_content_raise_if_none(SERVER_RSA_CRT_PATH)

    client_key = JWK.from_pem(client_key_content.encode("utf-8"))
    server_key = JWK.from_pem(server_key_content.encode("utf-8"))
    jwe_service = RSAJweService(SERVER_RSA_PRIV_KEY_PATH, SERVER_RSA_CRT_PATH)

    jwe_str = jwe_service.to_jwe({"key": "value"}, client_crt_content)
    jwe = JWE.from_jose_token(jwe_str)
    jwe.decrypt(client_key)
    jwt = JWT.from_jose_token(jwe.payload.decode("utf-8"))
    jwt.validate(jwe_service.get_pub_jwk())
    jwt.validate(server_key)
    assert jwt.claims == '{"key":"value"}'
