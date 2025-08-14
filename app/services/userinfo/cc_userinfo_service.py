from app.models.authentication_context import AuthenticationContext
from app.models.saml.artifact_response import ArtifactResponse
from app.services.encryption.jwt_service import JWTService
from app.services.userinfo.userinfo_service import UserinfoService


class CCUserinfoService(UserinfoService):
    def __init__(
        self,
        userinfo_jwt_service: JWTService,
        clients: dict,
    ):
        self._userinfo_jwt_service = userinfo_jwt_service
        self._clients = clients

    def request_userinfo_for_saml_artifact(
        self,
        authentication_context: AuthenticationContext,
        artifact_response: ArtifactResponse,
        subject_identifier: str,
    ) -> str:
        client_id = authentication_context.authorization_request["client_id"]
        client = self._clients[client_id]
        client_certificate = client["certificate"]

        bsn = artifact_response.get_bsn(authorization_by_proxy=False)
        loa_authn = artifact_response.loa_authn

        return self._userinfo_jwt_service.create_jwe(
            encryption_certificate=client_certificate,
            payload={
                "bsn": bsn,
                "session_id": authentication_context.session_id,
                "loa_authn": loa_authn,
                "aud": client_id,
                "sub": subject_identifier,
            },
        )

    def request_userinfo_for_exchange_token(
        self, authentication_context: AuthenticationContext, subject_identifier: str
    ) -> str:
        raise NotImplementedError()
