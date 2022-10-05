from fastapi import APIRouter, Request, Depends
from dependency_injector.wiring import inject, Provide

from app.providers.saml_provider import SAMLProvider


saml_router = APIRouter()


@saml_router.get("/acs")
@inject
def assertion_consumer_service(
    request: Request,
    saml_provider: SAMLProvider = Depends(Provide["services.saml_provider"]),
):
    return saml_provider.assertion_consumer_service(request)


@saml_router.get("/metadata/{id_provider}")
@inject
def metadata(
    id_provider: str,
    saml_provider: SAMLProvider = Depends(Provide["services.saml_provider"]),
):
    return saml_provider.metadata(id_provider)
