from typing import Any

# pylint: disable=
from app.misc.utils import file_content_raise_if_none
from app.models.authentication_context import AuthenticationContext
from app.models.saml.artifact_response import ArtifactResponse
from app.models.saml.saml_identity_provider import SamlIdentityProvider
from app.services.encryption.jwe_service_provider import JweServiceProvider
from app.services.userinfo.userinfo_service import UserinfoService


class CCUserinfoService(UserinfoService):
    def __init__(
        self, jwe_service_provider: JweServiceProvider, clients: dict, app_mode: str
    ):
        self._jwe_service_provider = jwe_service_provider
        self._clients = clients
        self._app_mode = app_mode

    def request_userinfo_for_digid_artifact(
        self,
        authentication_context: AuthenticationContext,
        artifact_response: ArtifactResponse,
        saml_identity_provider: SamlIdentityProvider,
    ) -> str:

        client_id = authentication_context.authorization_request["client_id"]
        bsn = artifact_response.get_bsn(authorization_by_proxy=False)
        jwe_service = self._jwe_service_provider.get_jwe_service(
            self._clients[client_id]["pubkey_type"]
        )
        if self._app_mode == "legacy":
            return jwe_service.box_encrypt(  # type:ignore
                bsn,
                file_content_raise_if_none(
                    self._clients[client_id]["client_public_key_path"]
                ),
            )
        content = file_content_raise_if_none(
            self._clients[client_id]["client_public_key_path"]
        )
        return jwe_service.to_jwe(
            {"bsn": bsn},  # type:ignore
            content,
        )

    def request_userinfo_for_exchange_token(
        self, authentication_context: AuthenticationContext, exchange_token: Any
    ) -> str:
        raise Exception("Not implemented")
