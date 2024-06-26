import logging
import time
from typing import Dict, Any, Optional, List

import requests
from cryptography.hazmat.primitives import hashes
from fastapi.security.utils import get_authorization_scheme_param
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT

from app.exceptions.max_exceptions import InvalidClientException, UnauthorizedError
from app.misc.utils import (
    file_content_raise_if_none,
    strip_cert,
    mocked_bsn_to_uzi_data,
)
from app.models.authentication_context import AuthenticationContext
from app.models.authentication_meta import AuthenticationMeta
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
        ssl_client_key_path: str,
        ssl_client_crt_path: str,
        ssl_client_verify: bool,
        cibg_exchange_token_endpoint: str,
        cibg_saml_endpoint: str,
        cibg_userinfo_issuer: str,
        cibg_userinfo_audience: str,
        req_issuer: str,
        jwt_expiration_duration: int,
        jwt_nbf_lag: int,
        external_http_requests_timeout_seconds: int,
        external_base_url: str,
    ):
        self._jwe_service_provider = jwe_service_provider
        self._environment = environment
        userinfo_request_signing_priv_key = file_content_raise_if_none(
            userinfo_request_signing_priv_key_path
        )
        userinfo_request_signing_crt = file_content_raise_if_none(
            userinfo_request_signing_crt_path
        )
        self._ssl_client_cert = (ssl_client_crt_path, ssl_client_key_path)
        self._ssl_client_verify = ssl_client_verify
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
        self._external_base_url = external_base_url

    def _create_jwt_payload(
        self,
        *,
        ura_pubkey_path: str,
        external_id: str,
        client_id: str,
        auth_type: str,
        json_schema: str,
        sub: str,
        authentication_meta: AuthenticationMeta,
        saml_id: Optional[str] = None,
        loa_authn: Optional[str] = None,
        exchange_token: Optional[str] = None,
        req_acme_tokens: Optional[List[str]] = None,
    ):
        ura_pubkey = file_content_raise_if_none(ura_pubkey_path)

        jwt_payload = {
            "json_schema": json_schema,
            "iss": self._cibg_userinfo_issuer,
            "aud": self._cibg_userinfo_audience,
            "nbf": int(time.time()) - self._jwt_nbf_lag,
            "exp": int(time.time()) + self._jwt_expiration_duration,
            "ura": external_id,
            "x5c": strip_cert(ura_pubkey),
            "auth_type": auth_type,
            "req_iss": self._req_issuer,
            "req_aud": client_id,
            "req_sub": sub,
            "meta": authentication_meta.model_dump(),
        }
        if loa_authn is not None:
            jwt_payload["loa_authn"] = loa_authn
        if req_acme_tokens is not None:
            jwt_payload["req_acme_tokens"] = req_acme_tokens
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
        json_schema: str,
        sub: str,
        authentication_meta: AuthenticationMeta,
        saml_id: Optional[str] = None,
        loa_authn: Optional[str] = None,
        data: Optional[str] = None,
        exchange_token: Optional[str] = None,
        req_acme_tokens: Optional[List[str]] = None,
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
            json_schema=json_schema,
            ura_pubkey_path=client["client_public_key_path"],
            external_id=external_id,
            client_id=client_id,
            auth_type=auth_type,
            saml_id=saml_id,
            loa_authn=loa_authn,
            exchange_token=exchange_token,
            req_acme_tokens=req_acme_tokens,
            sub=sub,
            authentication_meta=authentication_meta,
        )
        jwt_token = JWT(
            header=jwt_header,
            claims=jwt_payload,
        )
        jwt_token.make_signed_token(self._private_sign_jwk_key)
        headers = {"Authorization": f"Bearer {jwt_token.serialize()}"}
        if data is not None:
            headers["Content-Type"] = "application/xml"
        cibg_exchange_response = requests.post(
            cibg_endpoint,
            headers=headers,
            data=data,
            timeout=self._external_http_requests_timeout_seconds,
            cert=self._ssl_client_cert,
            verify=self._ssl_client_verify,
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
        subject_identifier: str,
    ) -> str:
        client_id = authentication_context.authorization_request["client_id"]
        client = self._clients[client_id]
        if (
            authentication_context.authentication_method == "digid_mock"
            and not self._environment.startswith("prod")
        ):
            return self._request_userinfo_for_mock_artifact(
                client_id=client_id,
                client=client,
                artifact_response=artifact_response,
                req_acme_tokens=authentication_context.req_acme_tokens,
                subject_identifier=subject_identifier,
                authentication_meta=authentication_context.authentication_meta,
            )
        return self._request_userinfo(
            cibg_endpoint=self._cibg_saml_endpoint,
            client_id=client_id,
            client=client,
            auth_type="digid",
            json_schema=self._external_base_url + "/json_schema.json",
            saml_id=artifact_response.root.attrib["ID"],
            loa_authn=artifact_response.loa_authn,
            data=artifact_response.to_envelope_string(),
            req_acme_tokens=authentication_context.req_acme_tokens,
            sub=subject_identifier,
            authentication_meta=authentication_context.authentication_meta,
        )

    def request_userinfo_for_exchange_token(
        self, authentication_context: AuthenticationContext, subject_identifier: str
    ) -> str:
        return self._request_userinfo(
            cibg_endpoint=self._cibg_exchange_token_endpoint,
            client_id=authentication_context.authorization_request["client_id"],
            client=self._clients[
                authentication_context.authorization_request["client_id"]
            ],
            auth_type="exchange_token",
            json_schema=self._external_base_url + "/json_schema.json",
            exchange_token=authentication_context.authentication_state[
                "exchange_token"
            ],
            saml_id=authentication_context.session_id,
            req_acme_tokens=authentication_context.req_acme_tokens,
            sub=subject_identifier,
            authentication_meta=authentication_context.authentication_meta,
        )

    def _request_userinfo_for_mock_artifact(
        self,
        client_id: str,
        client: Dict[str, Any],
        artifact_response: ArtifactResponse,
        req_acme_tokens: Optional[List[str]],
        subject_identifier: str,
        authentication_meta: AuthenticationMeta,
    ):
        bsn = artifact_response.get_bsn(False)
        ura_pubkey = file_content_raise_if_none(client["client_public_key_path"])

        if client["external_id"] == "*":
            uzi_data = mocked_bsn_to_uzi_data(bsn)
        else:
            uzi_data = mocked_bsn_to_uzi_data(
                bsn, relation_id_filter=client["external_id"]
            )

        data = {
            **uzi_data.dict(),
            "iss": self._req_issuer,
            "aud": client_id,
            "sub": subject_identifier,
            "json_schema": self._external_base_url + "/json_schema.json",
            "nbf": int(time.time()) - self._jwt_nbf_lag,
            "exp": int(time.time()) + self._jwt_expiration_duration,
            "x5c": strip_cert(ura_pubkey),
            "meta": authentication_meta.model_dump(),
        }
        if req_acme_tokens:
            data["acme_tokens"] = req_acme_tokens
        return self._jwe_service_provider.get_jwe_service(client["pubkey_type"]).to_jwe(
            data,
            file_content_raise_if_none(client["client_public_key_path"]),
        )
