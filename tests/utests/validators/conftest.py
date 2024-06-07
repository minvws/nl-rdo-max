import time
from typing import Dict, Any

import pytest
from configparser import ConfigParser

from cryptography.hazmat.primitives import hashes
from jwcrypto.jwt import JWT

from app.validators.token_authentication_validator import TokenAuthenticationValidator
from app.misc.utils import clients_from_json, load_jwk

# ID can be found in tests/clients.test.json
CLIENT_ID = "37692967-0a74-4e91-85ec-a4250e7ad5e8"


@pytest.fixture
def token_authentication_validator() -> TokenAuthenticationValidator:
    configuration_info = {
        "issuer": "example.com",
        "authorization_endpoint": "example.com/authorization_endpoint",
        "jwks_uri": "example.com/jwks_uri",
        "token_endpoint": "example.com/token_endpoint",
        "scopes_supported": "openid",
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["pairwise"],
        "token_endpoint_auth_methods_supported": ["none"],
        "claims_parameter_supported": True,
        "userinfo_endpoint": "example.com/userinfo_endpoint",
    }

    return TokenAuthenticationValidator(configuration_info)


@pytest.fixture
def client_id() -> str:
    return CLIENT_ID


@pytest.fixture
def client() -> Dict[str, Any]:
    config = ConfigParser()
    config.read("tests/max.test.conf")

    clients = clients_from_json(config.get("oidc", "clients_file"))
    client = clients[CLIENT_ID]
    client["private_key"] = load_jwk(client["client_private_key_path"])
    return client


@pytest.fixture
def invalid_client(client) -> Dict[str, Any]:
    return {**client, "client_authentication_method": "incorrect_method"}


@pytest.fixture
def valid_client_jwt(client, token_authentication_validator) -> JWT:
    return JWT(
        header={
            "alg": "RS256",
            "x5t": client["private_key"].thumbprint(hashes.SHA256()),
        },
        claims={
            "iss": CLIENT_ID,
            "sub": CLIENT_ID,
            "aud": token_authentication_validator.oidc_configuration_info.get(
                "token_endpoint"
            ),
            "exp": int(time.time()),
        },
    )


@pytest.fixture
def invalid_client_jwt(client) -> JWT:
    return JWT(
        header={
            "alg": "RS256",
            "x5t": client["private_key"].thumbprint(hashes.SHA256()),
        },
        claims={
            "iss": "37692967-0a74-4e91-85ec-a4250e7ad5e8",
            "sub": "37692967-0a74-4e91-85ec-a4250e7ad5e8",
            "aud": "incorrect_audience",
            "exp": int(time.time()),
        },
    )
