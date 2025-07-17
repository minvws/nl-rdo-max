import time

from app.misc.utils import file_content_raise_if_none, strip_cert
from app.models.authentication_context import AuthenticationContext
from app.models.saml.artifact_response import ArtifactResponse
from app.services.encryption.rsa_jwe_service import RSAJweService
from app.services.userinfo.userinfo_service import UserinfoService


class CCUserinfoService(UserinfoService):
    def __init__(
        self,
        jwe_service: RSAJweService,
        clients: dict,
        req_issuer: str,
        jwt_expiration_duration: int,
        jwt_nbf_lag: int,
    ):
        self._jwe_service = jwe_service
        self._clients = clients
        self._req_issuer = req_issuer
        self._jwt_expiration_duration = jwt_expiration_duration
        self._jwt_nbf_lag = jwt_nbf_lag

    def request_userinfo_for_saml_artifact(
        self,
        authentication_context: AuthenticationContext,
        artifact_response: ArtifactResponse,
        subject_identifier: str,
    ) -> str:
        client_id = authentication_context.authorization_request["client_id"]
        client = self._clients[client_id]
        client_pubkey = file_content_raise_if_none(client["client_public_key_path"])

        bsn = artifact_response.get_bsn(authorization_by_proxy=False)
        loa_authn = artifact_response.loa_authn

        return self._jwe_service.to_jwe(
            {
                "bsn": bsn,
                "session_id": authentication_context.session_id,
                "loa_authn": loa_authn,
                "iss": self._req_issuer,
                "aud": client_id,
                "sub": subject_identifier,
                "nbf": int(time.time()) - self._jwt_nbf_lag,
                "exp": int(time.time()) + self._jwt_expiration_duration,
                "x5c": strip_cert(client_pubkey),
            },
            client_pubkey,
        )

    def request_userinfo_for_exchange_token(
        self, authentication_context: AuthenticationContext, subject_identifier: str
    ) -> str:
        raise NotImplementedError()
