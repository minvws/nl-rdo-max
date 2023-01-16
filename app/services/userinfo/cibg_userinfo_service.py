import logging

from app.models.authentication_context import AuthenticationContext
from app.models.saml.artifact_response import ArtifactResponse
from app.models.saml.saml_identity_provider import SamlIdentityProvider
from app.services.userinfo.userinfo_service import UserinfoService

log = logging.getLogger(__name__)


class CIBGUserinfoService(UserinfoService):
    def __init__(self):
        # todo: Move userinfo services to saml
        pass

    def request_userinfo_for_artifact(
        self,
        authentication_context: AuthenticationContext,
        artifact_response: ArtifactResponse,
        saml_identity_provider: SamlIdentityProvider,
    ) -> str:
        raise Exception("unimplemented")
