import abc

from app.models.authentication_context import AuthenticationContext
from app.models.saml.artifact_response import ArtifactResponse


class UserinfoService(abc.ABC):
    @abc.abstractmethod
    def request_userinfo_for_digid_artifact(
        self,
        authentication_context: AuthenticationContext,
        artifact_response: ArtifactResponse,
        subject_identifier: str,
    ) -> str:
        pass

    @abc.abstractmethod
    def request_userinfo_for_exchange_token(
        self, authentication_context: AuthenticationContext, subject_identifier: str
    ) -> str:
        pass
