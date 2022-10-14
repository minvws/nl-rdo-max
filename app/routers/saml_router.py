from fastapi import APIRouter, Request, Depends
from dependency_injector.wiring import inject, Provide

from app.models.saml.assertion_consumer_service_request import AssertionConsumerServiceRequest
from app.providers.saml_provider import SAMLProvider


saml_router = APIRouter()


@saml_router.get("/acs")
@inject
def assertion_consumer_service(
    assertion_consumer_service_request: AssertionConsumerServiceRequest = Depends(AssertionConsumerServiceRequest.from_request),
    saml_provider: SAMLProvider = Depends(Provide["services.saml_provider"]),
):
    return saml_provider.assertion_consumer_service(assertion_consumer_service_request)


@saml_router.get("/metadata/{id_provider}")
@inject
def metadata(
    id_provider: str,
    saml_provider: SAMLProvider = Depends(Provide["services.saml_provider"]),
):
    return saml_provider.metadata(id_provider)
