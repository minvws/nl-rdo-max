# pylint: disable=
import time

from app.misc.utils import file_content_raise_if_none, strip_cert
from app.models.authentication_context import AuthenticationContext
from app.models.saml.artifact_response import ArtifactResponse
from app.models.saml.saml_identity_provider import SamlIdentityProvider
from app.services.encryption.jwe_service_provider import JweServiceProvider
from app.services.userinfo.userinfo_service import UserinfoService


class CCUserinfoService(UserinfoService):
    def __init__(
        self,
        jwe_service_provider: JweServiceProvider,
        clients: dict,
        app_mode: str,
        req_issuer: str,
        jwt_expiration_duration: int,
        jwt_nbf_lag: int,
    ):
        self._jwe_service_provider = jwe_service_provider
        self._clients = clients
        self._app_mode = app_mode
        self._req_issuer = req_issuer
        self._jwt_expiration_duration = jwt_expiration_duration
        self._jwt_nbf_lag = jwt_nbf_lag

    def request_userinfo_for_digid_artifact(
        self,
        authentication_context: AuthenticationContext,
        artifact_response: ArtifactResponse,
        saml_identity_provider: SamlIdentityProvider,
    ) -> str:
        client_id = authentication_context.authorization_request["client_id"]
        client = self._clients[client_id]
        client_pubkey = file_content_raise_if_none(client["client_public_key_path"])

        bsn = artifact_response.get_bsn(authorization_by_proxy=False)
        loa_authn = artifact_response.loa_authn

        jwe_service = self._jwe_service_provider.get_jwe_service(client["pubkey_type"])
        if self._app_mode == "legacy":
            return jwe_service.box_encrypt(  # type:ignore
                bsn, client_pubkey
            )

        return self._jwe_service_provider.get_jwe_service(client["pubkey_type"]).to_jwe(
            {
                "bsn": bsn,
                "loa_authn": loa_authn,
                "iss": self._req_issuer,
                "aud": client_id,
                "nbf": int(time.time()) - self._jwt_nbf_lag,
                "exp": int(time.time()) + self._jwt_expiration_duration,
                "x5c": strip_cert(client_pubkey),
            },
            client_pubkey,
        )

    def request_userinfo_for_exchange_token(
        self, authentication_context: AuthenticationContext
    ) -> str:
        raise NotImplementedError()
