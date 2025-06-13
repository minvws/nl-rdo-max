import logging
import time

from app.misc.utils import (
    file_content_raise_if_none,
    strip_cert,
)
from app.models.authentication_context import AuthenticationContext
from app.models.saml.artifact_response import ArtifactResponse
from app.services.encryption.jwt_service_factory import JWTServiceFactory
from app.services.userinfo.userinfo_service import UserinfoService

log = logging.getLogger(__name__)


# pylint: disable=too-many-arguments, too-many-positional-arguments, too-many-instance-attributes
class EherkenningUserinfoService(UserinfoService):
    def __init__(
        self,
        jwt_service_factory: JWTServiceFactory,
        clients: dict,
        userinfo_request_signing_priv_key_path: str,
        userinfo_request_signing_crt_path: str,
        req_issuer: str,
        jwt_expiration_duration: int,
        jwt_nbf_lag: int,
        external_base_url: str,
    ):
        self.jwt_service = jwt_service_factory.create(
            userinfo_request_signing_priv_key_path, userinfo_request_signing_crt_path
        )
        self._clients = clients
        self._jwt_expiration_duration = jwt_expiration_duration
        self._jwt_nbf_lag = jwt_nbf_lag
        self._req_issuer = req_issuer
        self._external_base_url = external_base_url

    def request_userinfo_for_saml_artifact(
        self,
        authentication_context: AuthenticationContext,
        artifact_response: ArtifactResponse,
        subject_identifier: str,
    ) -> str:
        client_id = authentication_context.authorization_request["client_id"]
        client = self._clients[client_id]

        kvk = artifact_response.get_kvk(False)

        kvk_pubkey = file_content_raise_if_none(client["client_public_key_path"])

        kvk_number = kvk.split("-")[0]
        kvk_name = kvk.split("-")[1]
        data = {
            "kvk_number": kvk_number,
            "kvk_name": kvk_name,
            "iss": self._req_issuer,
            "aud": client_id,
            "sub": subject_identifier,
            "json_schema": self._external_base_url + "/json_schema.json",
            "nbf": int(time.time()) - self._jwt_nbf_lag,
            "exp": int(time.time()) + self._jwt_expiration_duration,
            "x5c": strip_cert(kvk_pubkey),
        }
        if authentication_context.req_acme_tokens:
            data["acme_tokens"] = authentication_context.req_acme_tokens

        jwe_token = self.jwt_service.create_jwe(client["public_key"], data)

        return jwe_token

    def request_userinfo_for_exchange_token(
        self, authentication_context: AuthenticationContext, subject_identifier: str
    ) -> str:
        raise NotImplementedError(
            "EherkenningUserinfoService does not support request_userinfo_for_exchange_token"
        )
