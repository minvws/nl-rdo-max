import logging

from dependency_injector.wiring import inject, Provide
from fastapi import APIRouter, Request, Depends
from starlette.responses import JSONResponse

from app.dependency_injection.config import RouterConfig
from app.exceptions.max_exceptions import UnauthorizedError
from app.exceptions.oidc_exception_handlers import handle_exception_redirect
from app.models.authorize_request import AuthorizeRequest
from app.models.token_request import TokenRequest
from app.providers.oidc_provider import OIDCProvider

oidc_router = APIRouter()

logger = logging.getLogger(__name__)


@oidc_router.get("/.well-known/openid-configuration")
@inject
def well_known(
    oidc_provider: OIDCProvider = Depends(Provide["services.oidc_provider"]),
):
    return oidc_provider.well_known()


@oidc_router.get(RouterConfig.authorize_endpoint)
@inject
def authorize(
    request: Request,
    authorize_req: AuthorizeRequest = Depends(),
    oidc_provider: OIDCProvider = Depends(Provide["services.oidc_provider"]),
):
    return oidc_provider.present_login_options_or_authorize(request, authorize_req)


@oidc_router.post(RouterConfig.accesstoken_endpoint)
@inject
async def accesstoken(
    request: Request,
    oidc_provider: OIDCProvider = Depends(Provide["services.oidc_provider"]),
):
    return oidc_provider.token(
        TokenRequest.from_body_query_string((await request.body()).decode("utf-8")),
        request.headers,
    )


@oidc_router.get("/continue")
@inject
async def _continue(
    state: str,
    request: Request,
    oidc_provider: OIDCProvider = Depends(Provide["services.oidc_provider"]),
):
    try:
        return oidc_provider.authenticate_with_exchange_token(state)
    except UnauthorizedError as unauthorized_error:
        logger.debug("UnauthorizedError: %s", unauthorized_error)
        return handle_exception_redirect(
            request,
            unauthorized_error.error,
            unauthorized_error.error_description,
            status_code=403,
        )


@oidc_router.get(RouterConfig.jwks_endpoint)
@inject
async def jwks(
    oidc_provider: OIDCProvider = Depends(Provide["services.oidc_provider"]),
):
    return oidc_provider.jwks()


# Post is legacy until signing service supports get user_info
@oidc_router.post(RouterConfig.userinfo_endpoint)
@oidc_router.get(RouterConfig.userinfo_endpoint)
@inject
def userinfo(
    request: Request,
    oidc_provider: OIDCProvider = Depends(Provide["services.oidc_provider"]),
):
    return oidc_provider.userinfo(request)


@oidc_router.get("/json-schema.json")
@inject
def json_schema(
    schema_content: str = Depends(Provide["services.json_schema"]),
):
    return JSONResponse(content=schema_content)
