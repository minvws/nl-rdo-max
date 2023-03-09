import json
import logging
import time

import requests
from cryptography.hazmat.primitives import hashes
from fastapi.security.utils import get_authorization_scheme_param
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT

from app.exceptions.max_exceptions import InvalidClientException, UnauthorizedError
from app.misc.utils import file_content_raise_if_none, strip_cert
from app.models.authentication_context import AuthenticationContext
from app.models.saml.artifact_response import ArtifactResponse
from app.models.saml.saml_identity_provider import SamlIdentityProvider
from app.services.userinfo.userinfo_service import UserinfoService

log = logging.getLogger(__name__)


class CIBGUserinfoService(UserinfoService):
    def __init__(
        self,
        userinfo_request_signing_priv_key_path: str,
        userinfo_request_signing_crt_path: str,
        clients: dict,
        cibg_exchange_token_endpoint,
        jwt_issuer: str,
        jwt_expiration_duration: int,
        jwt_nbf_lag: int,
    ):
        userinfo_request_signing_priv_key = file_content_raise_if_none(
            userinfo_request_signing_priv_key_path
        )
        userinfo_request_signing_crt = file_content_raise_if_none(
            userinfo_request_signing_crt_path
        )
        self._private_sign_jwk_key = JWK.from_pem(
            userinfo_request_signing_priv_key.encode("utf-8")
        )
        self._public_sign_jwk_key = JWK.from_pem(
            userinfo_request_signing_crt.encode("utf-8")
        )
        self._clients = clients
        self._cibg_exchange_token_endpoint = cibg_exchange_token_endpoint
        self._jwt_issuer = jwt_issuer
        self._jwt_expiration_duration = jwt_expiration_duration
        self._jwt_nbf_lag = jwt_nbf_lag

    def request_userinfo_for_digid_artifact(
        self,
        authentication_context: AuthenticationContext,
        artifact_response: ArtifactResponse,
        saml_identity_provider: SamlIdentityProvider,
    ) -> str:
        raise Exception("unimplemented")

    def request_userinfo_for_exchange_token(
        self, authentication_context: AuthenticationContext, exchange_token: str
    ) -> str:
        client = self._clients[
            authentication_context.authorization_request["client_id"]
        ]
        external_id = "*"
        if "external_id" in client:
            external_id = client["external_id"]
        if "pubkey_type" not in client or client["pubkey_type"] != "RSA":
            raise InvalidClientException(
                error_description="client pubkey_type should be RSA"
            )
        ura_pubkey = file_content_raise_if_none(client["client_public_key_path"])
        jwt_header = {
            "typ": "JWT",
            "cty": "JWT",
            "alg": "RS256",
            "enc": "A128CBC-HS256",
            "x5t": self._private_sign_jwk_key.thumbprint(hashes.SHA256()),
        }
        jwt_payload = {
            "req_iss": self._jwt_issuer,
            "aud": "cibg",
            "nbf": int(time.time()) - self._jwt_nbf_lag,
            "exp": int(time.time()) + self._jwt_expiration_duration,
            "ura": external_id,
            "x5c": strip_cert(ura_pubkey),
            "loa_authn": "substantial",
            "auth_type": "exchange_token",
        }
        jwt_token = JWT(
            header=jwt_header,
            claims=jwt_payload,
        )
        jwt_token.make_signed_token(self._private_sign_jwk_key)
        cibg_exchange_response = requests.post(
            self._cibg_exchange_token_endpoint,
            headers={
                "Authorization": f"Bearer {jwt_token.serialize()}",
                "Content-Type": "application/json",
            },
            data=json.dumps({"exchange_token": exchange_token}),
            timeout=60,
        )
        if cibg_exchange_response.status_code >= 400:
            raise UnauthorizedError(
                error_description="Invalid response from uzi register"
            )
        scheme, jwe_token = get_authorization_scheme_param(
            cibg_exchange_response.headers["Authorization"]
        )
        if scheme != "Bearer":
            raise RuntimeError(f"Unexpected header scheme: {scheme}")
        return jwe_token
