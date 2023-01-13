import abc

from app.models.authentication_context import AuthenticationContext
from app.models.saml.saml_identity_provider import SamlIdentityProvider
from app.models.saml.artifact_response import ArtifactResponse


class UserinfoService(abc.ABC):
    @abc.abstractmethod
    def request_userinfo_for_artifact(
            self,
            authentication_context: AuthenticationContext,
            saml_artifact: ArtifactResponse,
            saml_identity_provider: SamlIdentityProvider
    ) -> str:
        pass
