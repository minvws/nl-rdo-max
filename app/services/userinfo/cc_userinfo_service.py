import logging
from typing import Dict, Any

from app.exceptions.max_exceptions import UnauthorizedError
from app.misc.utils import file_content_raise_if_none
from app.models.authentication_context import AuthenticationContext
from app.models.saml.artifact_response import ArtifactResponse
from app.models.saml.saml_identity_provider import SamlIdentityProvider
from app.services.encryption.jwe_service import JweService
from app.services.userinfo.userinfo_service import UserinfoService


class CCUserinfoService(UserinfoService):
    def __init__(self, jwe_service: JweService, clients: dict, app_mode: str):
        self._jwe_service = jwe_service
        self._clients = clients
        self._app_mode = app_mode

    def request_userinfo_for_artifact(
        self,
        authentication_context: AuthenticationContext,
        artifact_response: ArtifactResponse,
        saml_identity_provider: SamlIdentityProvider
    ) -> str:

        client_id = authentication_context.authorization_request["client_id"]
        bsn = artifact_response.get_bsn(authorization_by_proxy=False)
        if self._app_mode == "legacy":
            return self._jwe_service.box_encrypt(  # type:ignore
                bsn,
                self._clients[client_id]["client_public_nacl_key"],
            )
        content = file_content_raise_if_none(
            self._clients[client_id]["client_certificate_path"]
        )
        return self._jwe_service.to_jwe(
            {"bsn": bsn},  # type:ignore
            content,
        )

    # todo: Get rid of the notImplementedError
    def irma_disclosure(self, userinfo: Dict[Any, Any]):
        raise NotImplementedError()

    def from_irma_disclosure(self, irma_disclosure):
        raise NotImplementedError()
