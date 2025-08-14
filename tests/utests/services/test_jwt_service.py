import json

from jwcrypto.jwe import JWE
from jwcrypto.jwt import JWT

from app.services.encryption.jwt_service import JWTService, from_jwt


def test_jwt_service_factory(jwt_service) -> None:
    assert isinstance(jwt_service, JWTService)


def test_from_jwt(jwt_service, session_jwt_sign_priv_key) -> None:
    expected_claims = {"claims": "some example data"}

    jwt_token = jwt_service.create_jwt(expected_claims)
    actual_claims = from_jwt(session_jwt_sign_priv_key, jwt_token)

    assert actual_claims["claims"] == expected_claims["claims"]


def test_from_jwe(
    jwt_service, test_client, test_client_private_key, session_jwt_sign_priv_key
) -> None:
    expected_claims = {"claims": "some example data"}

    # Create a JWTService instance for the client as the client will create the JWE for MAX
    client_jwt_service = JWTService(
        issuer="some-issuer",
        signing_certificate=test_client["certificate"],
        signing_private_key=test_client_private_key,
    )

    # Create a JWE token using the client's key and encrypt it for MAX
    max_certificate = jwt_service._signing_certificate
    jwe_token = client_jwt_service.create_jwe(max_certificate, expected_claims)

    # Decrypt the JWE token using Max's JWTService and check the signing certificate
    actual_claims = jwt_service.from_jwe(
        jwt_pub_key=test_client["certificate"].jwk,
        jwe=jwe_token,
    )

    assert actual_claims["claims"] == expected_claims["claims"]


def test_to_jwe(
    jwt_service,
    test_client,
    test_client_private_key,
):
    # Create a JWE from a payload and the client's certificate
    payload = {"key": "value"}
    jwe_str = jwt_service.create_jwe(
        encryption_certificate=test_client["certificate"], payload=payload
    )
    assert isinstance(jwe_str, str) and jwe_str, "JWE string should not be empty"

    # Parse and decrypt the JWE using the client's private key
    jwe = JWE.from_jose_token(jwe_str)
    jwe.decrypt(test_client_private_key)

    # Parse the decrypted payload as a JWT and validate it
    jwt = JWT.from_jose_token(jwe.payload.decode("utf-8"))
    jwt.validate(jwt_service.get_signing_certificate().jwk)

    # Check the claims in the JWT
    claims = json.loads(jwt.claims)
    assert claims["key"] == "value"
    assert claims.get("exp") is not None, "exp claim should be present"
    assert claims.get("nbf") is not None, "nbf claim should be present"
