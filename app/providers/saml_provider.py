import logging
from typing import Dict

from fastapi import Response, HTTPException

from app.exceptions.max_exceptions import UnauthorizedError
from app.exceptions.oidc_exceptions import TEMPORARILY_UNAVAILABLE
from app.misc.rate_limiter import RateLimiter
from app.models.saml.artifact_response import ArtifactResponse
from app.models.saml.artifact_response_mock import ArtifactResponseMock
from app.models.saml.assertion_consumer_service_request import (
    AssertionConsumerServiceRequest,
)
from app.providers.oidc_provider import OIDCProvider
from app.services.saml.saml_identity_provider_service import SamlIdentityProviderService
from app.services.saml.saml_response_factory import SamlResponseFactory
from app.services.userinfo.userinfo_service import UserinfoService

log = logging.getLogger(__package__)


class SAMLProvider:
    def __init__(
        self,
        saml_response_factory: SamlResponseFactory,
        oidc_provider: OIDCProvider,
        saml_identity_provider_service: SamlIdentityProviderService,
        rate_limiter: RateLimiter,
        userinfo_service: UserinfoService,
        environment: str,
        clients: Dict[str, Dict],
    ):
        self._saml_response_factory = saml_response_factory
        self._oidc_provider = oidc_provider
        self._saml_identity_provider_service = saml_identity_provider_service
        self._rate_limiter = rate_limiter
        self._userinfo_service = userinfo_service
        self._environment = environment
        self._clients = clients

    def handle_assertion_consumer_service(
        self, request: AssertionConsumerServiceRequest
    ):
        authentication_context = self._oidc_provider.get_authentication_request_state(
            request.RelayState
        )

        if (
            not self._environment.startswith("prod")
            and authentication_context.authentication_method == "digid_mock"
        ):
            artifact_response: ArtifactResponse = ArtifactResponseMock(request.SAMLart)
        else:
            identity_provider = (
                self._saml_identity_provider_service.get_identity_provider(
                    authentication_context.authentication_state[
                        "identity_provider_name"
                    ]
                )
            )
            artifact_response = identity_provider.resolve_artifact(request.SAMLart)
        if artifact_response.saml_status.code.lower() != "success":
            if artifact_response.saml_status.message is not None:
                error_description = artifact_response.saml_status.message
            else:
                error_description = TEMPORARILY_UNAVAILABLE
            raise UnauthorizedError(
                log_message="Invalid saml response received with status: "
                f"{artifact_response.saml_status.code}, {artifact_response.saml_status.message}",
                error_description=error_description,
            )

        pyop_authorization_response = self._oidc_provider.py_op_authorize(
            authentication_context.authorization_request
        )
        subject_identifier = self._oidc_provider.get_subject_identifier(
            pyop_authorization_response["code"]
        )

        userinfo = self._userinfo_service.request_userinfo_for_digid_artifact(
            authentication_context,
            artifact_response,
            subject_identifier,
        )
        return self._oidc_provider.authenticate(
            authentication_context, userinfo, pyop_authorization_response
        )

    def metadata(self, id_provider_name: str):
        """
        Endpoint retrieving metadata for the specified identity providers if configured properly.
        """
        identity_provider = self._saml_identity_provider_service.get_identity_provider(
            id_provider_name
        )
        errors = identity_provider.sp_metadata.validate()
        if len(errors) == 0:
            return Response(
                content=identity_provider.sp_metadata.get_xml().decode(),
                media_type="application/xml",
            )

        raise HTTPException(status_code=500, detail=", ".join(errors))
