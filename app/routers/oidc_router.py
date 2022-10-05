from fastapi import APIRouter, Request, Depends
from dependency_injector.wiring import inject, Provide

from app.providers.oidc_provider import OIDCProvider
from app.dependency_injection.config import RouterConfig
from app.models.authorize_request import AuthorizeRequest


oidc_router = APIRouter()


@oidc_router.get("/.well-known/openid-configuration")
@inject
def well_known(
    oidc_provider: OIDCProvider = Depends(Provide["services.oidc_provider"])
):
    return oidc_provider.well_known()


@oidc_router.get(RouterConfig.authorize_endpoint)
@inject
def authorize(
    request: Request,
    authorize_req: AuthorizeRequest = Depends(),
    oidc_provider: OIDCProvider = Depends(Provide["services.oidc_provider"]),
):
    return oidc_provider.authorize(authorize_req, request)
