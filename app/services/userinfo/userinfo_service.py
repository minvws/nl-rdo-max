import abc
from typing import Any, Dict

from app.models.authentication_context import AuthenticationContext
from app.models.saml.saml_identity_provider import SamlIdentityProvider

#todo is this used?
class UserinfoService(abc.ABC):
    @abc.abstractmethod
    def request_userinfo_for_artifact(
            self,
            authentication_context: AuthenticationContext,
            saml_artifact: str,
            saml_identity_provider: SamlIdentityProvider
    ) -> str:
        pass

    @abc.abstractmethod
    def irma_disclosure(self, userinfo: Dict[Any, Any]):
        pass

    @abc.abstractmethod
    def from_irma_disclosure(self, irma_disclosure):
        pass
