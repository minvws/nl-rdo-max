import json
import logging
from typing import Optional
from unittest.mock import MagicMock


from dependency_injector.wiring import inject, Provide
from fastapi import APIRouter, Request, Depends, HTTPException
from starlette.responses import JSONResponse

from pyop.message import AuthorizationRequest


from app.dependency_injection.config import RouterConfig
from app.exceptions.max_exceptions import InvalidRequestException
from app.exceptions.oidc_exceptions import INVALID_REQUEST
from app.models.authentication_context import AuthenticationContext
from app.models.authentication_meta import AuthenticationMeta
from app.models.authorize_request import AuthorizeRequest
from app.models.token_request import TokenRequest
from app.models.saml.artifact_response_mock import ArtifactResponseMock
from app.providers.oidc_provider import OIDCProvider
from app.services.userinfo.userinfo_service import UserinfoService


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
    try:
        return oidc_provider.token(
            TokenRequest.from_body_query_string((await request.body()).decode("utf-8")),
            request.headers,
        )
    except ValueError as exception:
        raise HTTPException(status_code=400, detail=str(exception)) from exception


@oidc_router.get("/continue")
@inject
async def _continue(
    state: str,
    exchange_token: Optional[str] = None,
    error: Optional[str] = None,
    error_description: Optional[str] = None,
    error_details: Optional[str] = None,
    oidc_provider: OIDCProvider = Depends(Provide["services.oidc_provider"]),
):
    if not error:
        if not exchange_token:
            raise InvalidRequestException(
                error=INVALID_REQUEST,
                error_description=INVALID_REQUEST,
                log_message=error_details,
            )
        return oidc_provider.authenticate_with_exchange_token(state, exchange_token)
    raise InvalidRequestException(
        error=error,
        error_description=error_description if error_description is not None else error,
        log_message=error_details,
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


@oidc_router.get("/vad/userinfo/{bsn}")
@inject
async def vad_userinfo(
    bsn: str,
    vad_user_provider: UserinfoService = Depends(Provide["services.userinfo_service"]),
):
    authentication_context = AuthenticationContext(
        authorization_request=MagicMock(spec=AuthorizationRequest),
        authorization_by_proxy=True,
        authentication_method="method",
        authentication_state={},
        session_id="session_id",
        req_acme_tokens=None,
        authentication_meta=MagicMock(spec=AuthenticationMeta),
    )
    artifact_response: ArtifactResponseMock = ArtifactResponseMock(
        artifact_response_str=bsn
    )
    subject_identifier: str = "subject_identifier"
    userinfo_json_str: str = await vad_user_provider.request_userinfo_for_digid_artifact(
        authentication_context, artifact_response, subject_identifier
    )
    userinfo_dict = json.loads(userinfo_json_str)
    return JSONResponse(content=userinfo_dict)
