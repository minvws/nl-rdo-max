import abc

from typing import Any

from app.models.authentication_context import AuthenticationContext
from app.models.saml.saml_identity_provider import SamlIdentityProvider
from app.models.saml.artifact_response import ArtifactResponse


class UserinfoService(abc.ABC):
    @abc.abstractmethod
    def request_userinfo_for_digid_artifact(
        self,
        authentication_context: AuthenticationContext,
        artifact_response: ArtifactResponse,
        saml_identity_provider: SamlIdentityProvider,
    ) -> str:
        pass

    @abc.abstractmethod
    def request_userinfo_for_irma_response(
            self,
            authentication_context: AuthenticationContext,
            irma_response: Any
    ) -> str:
        pass
