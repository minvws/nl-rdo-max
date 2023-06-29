import logging
import time
from typing import Dict, Union, Any

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
from app.services.encryption.jwe_service_provider import JweServiceProvider
from app.services.userinfo.userinfo_service import UserinfoService

log = logging.getLogger(__name__)


# pylint: disable=too-many-arguments, too-many-instance-attributes
class CIBGUserinfoService(UserinfoService):
    def __init__(
        self,
        jwe_service_provider: JweServiceProvider,
        environment: str,
        clients: dict,
        userinfo_request_signing_priv_key_path: str,
        userinfo_request_signing_crt_path: str,
        cibg_exchange_token_endpoint: str,
        cibg_saml_endpoint: str,
        cibg_userinfo_issuer: str,
        cibg_userinfo_audience: str,
        req_issuer: str,
        jwt_expiration_duration: int,
        jwt_nbf_lag: int,
        external_http_requests_timeout_seconds: int,
    ):
        self._jwe_service_provider = jwe_service_provider
        self._environment = environment
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
        self._cibg_saml_endpoint = cibg_saml_endpoint
        self._cibg_userinfo_issuer = cibg_userinfo_issuer
        self._cibg_userinfo_audience = cibg_userinfo_audience
        self._req_issuer = req_issuer
        self._jwt_expiration_duration = jwt_expiration_duration
        self._jwt_nbf_lag = jwt_nbf_lag
        self._external_http_requests_timeout_seconds = (
            external_http_requests_timeout_seconds
        )

    def _create_jwt_payload(
        self,
        *,
        ura_pubkey_path: str,
        external_id: str,
        client_id: str,
        auth_type: str,
        saml_id: Union[str, None] = None,
        loa_authn: Union[str, None] = None,
        exchange_token: Union[str, None] = None,
        req_acme_token: Union[str, None] = None,
    ):
        ura_pubkey = file_content_raise_if_none(ura_pubkey_path)

        jwt_payload = {
            "iss": self._cibg_userinfo_issuer,
            "aud": self._cibg_userinfo_audience,
            "nbf": int(time.time()) - self._jwt_nbf_lag,
            "exp": int(time.time()) + self._jwt_expiration_duration,
            "ura": external_id,
            "x5c": strip_cert(ura_pubkey),
            "auth_type": auth_type,
            "req_iss": self._req_issuer,
            "req_aud": client_id,
        }
        if loa_authn is not None:
            jwt_payload["loa_authn"] = loa_authn
        if req_acme_token is not None:
            jwt_payload["req_acme_token"] = req_acme_token
        if saml_id is not None:
            jwt_payload["saml_id"] = saml_id
        if exchange_token is not None:
            jwt_payload["exchange_token"] = exchange_token
        return jwt_payload

    def _request_userinfo(
        self,
        cibg_endpoint: str,
        client_id: str,
        client: Dict[str, Any],
        auth_type: str,
        saml_id: Union[str, None] = None,
        loa_authn: Union[str, None] = None,
        data: Union[str, None] = None,
        exchange_token: Union[str, None] = None,
    ):
        external_id = "*"
        if "external_id" in client:
            external_id = client["external_id"]
            if "pubkey_type" not in client or client["pubkey_type"] != "RSA":
                raise InvalidClientException(
                    error_description="client pubkey_type should be RSA"
                )
        jwt_header = {
            "typ": "JWT",
            "cty": "JWT",
            "alg": "RS256",
            "enc": "A128CBC-HS256",
            "x5t": self._private_sign_jwk_key.thumbprint(hashes.SHA256()),
        }
        jwt_payload = self._create_jwt_payload(
            ura_pubkey_path=client["client_public_key_path"],
            external_id=external_id,
            client_id=client_id,
            auth_type=auth_type,
            saml_id=saml_id,
            loa_authn=loa_authn,
            exchange_token=exchange_token,
            req_acme_token=None,
        )
        jwt_token = JWT(
            header=jwt_header,
            claims=jwt_payload,
        )
        jwt_token.make_signed_token(self._private_sign_jwk_key)
        cibg_exchange_response = requests.post(
            cibg_endpoint,
            headers={
                "Authorization": f"Bearer {jwt_token.serialize()}",
                "Content-Type": "application/json",
            },
            data=data,
            timeout=self._external_http_requests_timeout_seconds,
        )
        if cibg_exchange_response.status_code >= 400:
            raise UnauthorizedError(
                error_description="Invalid response from uzi register",
            )
        scheme, jwe_token = get_authorization_scheme_param(
            cibg_exchange_response.headers["Authorization"]
        )
        if scheme != "Bearer":
            raise RuntimeError(f"Unexpected header scheme: {scheme}")
        return jwe_token

    def request_userinfo_for_digid_artifact(
        self,
        authentication_context: AuthenticationContext,
        artifact_response: ArtifactResponse,
        saml_identity_provider: SamlIdentityProvider,
    ) -> str:
        client_id = authentication_context.authorization_request["client_id"]
        client = self._clients[client_id]
        if (
            authentication_context.authentication_method == "digid_mock"
            and not self._environment.startswith("prod")
        ):
            return self._request_userinfo_for_mock_artifact(
                client_id=client_id, client=client, artifact_response=artifact_response
            )
        return self._request_userinfo(
            cibg_endpoint=self._cibg_saml_endpoint,
            client_id=client_id,
            client=client,
            auth_type="digid",
            saml_id=artifact_response.root.attrib["ID"],
            loa_authn=artifact_response.loa_authn,
            data=artifact_response.to_envelope_string(),
        )

    def request_userinfo_for_exchange_token(
        self, authentication_context: AuthenticationContext
    ) -> str:
        return self._request_userinfo(
            cibg_endpoint=self._cibg_exchange_token_endpoint,
            client_id=authentication_context.authorization_request["client_id"],
            client=self._clients[
                authentication_context.authorization_request["client_id"]
            ],
            auth_type="exchange_token",
            exchange_token=authentication_context.authentication_state[
                "exchange_token"
            ],
        )

    def _request_userinfo_for_mock_artifact(
        self, client_id: str, client: Any, artifact_response: ArtifactResponse
    ):
        bsn = artifact_response.get_bsn(False)
        relations = []
        if "disclosure_clients" in client:
            for disclosure_client in client["disclosure_clients"]:
                relations.append(
                    {
                        "ura": self._clients[disclosure_client]["external_id"],
                        "entity_name": self._clients[disclosure_client]["name"],
                        "roles": ["01.041", "30.000", "01.010", "01.011"],
                    }
                )
        else:
            relations.append(
                {
                    "ura": client["external_id"],
                    "entity_name": client["name"],
                    "roles": ["01.041", "30.000", "01.010", "01.011"],
                }
            )
        ura_pubkey = file_content_raise_if_none(client["client_public_key_path"])
        return self._jwe_service_provider.get_jwe_service(client["pubkey_type"]).to_jwe(
            {
                # todo create json schema
                "iss": self._req_issuer,
                "aud": client_id,
                "json_schema": "https://www.inge6.nl/json_schema_v1.json",
                "initials": "J.J",
                "surname_prefix": "van der",
                "surname": "Jansen",
                "loa_authn": "http://eidas.europa.eu/LoA/substantial",
                "loa_uzi": "http://eidas.europa.eu/LoA/substantial",
                "uzi_id": bsn,
                "relations": relations,
                "nbf": int(time.time()) - self._jwt_nbf_lag,
                "exp": int(time.time()) + self._jwt_expiration_duration,
                "x5c": strip_cert(ura_pubkey),
            },
            file_content_raise_if_none(client["client_public_key_path"]),
        )
