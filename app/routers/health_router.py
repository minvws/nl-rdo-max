from dependency_injector.wiring import inject, Provide
from fastapi import APIRouter, Request, Depends

from app.services.saml.saml_identity_provider_service import SamlIdentityProviderService
from app.services.saml.saml_response_factory import SamlResponseFactory

health_router = APIRouter()


@health_router.get("/health")
@inject
async def health(
        request: Request,
        saml_response_factory: SamlResponseFactory = Depends(Provide["services.saml_response_factory"]),
        saml_identity_provider_service: SamlIdentityProviderService =
        Depends(Provide["services.saml_identity_provider_service"])
):
    pass
    # todo: Dit fixen, based on failed logins?
