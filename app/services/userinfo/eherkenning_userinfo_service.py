import logging

from app.models.authentication_context import AuthenticationContext
from app.models.saml.artifact_response import ArtifactResponse

from app.services.encryption.jwt_service import JWTService
from app.services.userinfo.userinfo_service import UserinfoService

log = logging.getLogger(__name__)


class EherkenningUserinfoService(UserinfoService):
    def __init__(
        self,
        userinfo_jwt_service: JWTService,
        clients: dict,
        external_base_url: str,
    ):
        self._userinfo_jwt_service = userinfo_jwt_service
        self._clients = clients
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

        data = {
            "kvk_number": kvk,
            "aud": client_id,
            "sub": subject_identifier,
            "json_schema": self._external_base_url + "/json_schema.json",
        }
        if authentication_context.req_acme_tokens:
            data["acme_tokens"] = authentication_context.req_acme_tokens

        jwe_token = self._userinfo_jwt_service.create_jwe(
            encryption_certificate=client["certificate"], payload=data
        )

        return jwe_token

    def request_userinfo_for_exchange_token(
        self, authentication_context: AuthenticationContext, subject_identifier: str
    ) -> str:
        raise NotImplementedError(
            "EherkenningUserinfoService does not support request_userinfo_for_exchange_token"
        )
