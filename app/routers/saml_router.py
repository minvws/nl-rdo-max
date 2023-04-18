import logging

from dependency_injector.wiring import inject, Provide
from fastapi import APIRouter, Depends
from starlette.requests import Request

from app.exceptions.max_exceptions import UnauthorizedError
from app.exceptions.oidc_exception_handlers import handle_exception_redirect
from app.models.saml.assertion_consumer_service_request import (
    AssertionConsumerServiceRequest,
)
from app.providers.saml_provider import SAMLProvider

saml_router = APIRouter()

logger = logging.getLogger(__name__)


@saml_router.get("/acs")
@inject
def assertion_consumer_service(
    request: Request,
    assertion_consumer_service_request: AssertionConsumerServiceRequest = Depends(
        AssertionConsumerServiceRequest.from_request
    ),
    saml_provider: SAMLProvider = Depends(Provide["services.saml_provider"]),
):
    try:
        return saml_provider.handle_assertion_consumer_service(
            assertion_consumer_service_request
        )
    except UnauthorizedError as unauthorized_error:
        logger.debug("UnauthorizedError: %s", unauthorized_error)
        return handle_exception_redirect(
            request, unauthorized_error.error, unauthorized_error.error_description
        )


@saml_router.get("/metadata/{id_provider}")
@inject
def metadata(
    id_provider: str,
    saml_provider: SAMLProvider = Depends(Provide["services.saml_provider"]),
):
    return saml_provider.metadata(id_provider)
