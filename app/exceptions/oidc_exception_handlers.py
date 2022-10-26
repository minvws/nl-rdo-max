from fastapi import Request
from fastapi.templating import Jinja2Templates

from app.exceptions.max_exceptions import ServerErrorException
from app.exceptions.oidc_exceptions import (
    InvalidClientException,
    InvalidRedirectUriException,
    UNAUTHORIZED_CLIENT,
    SERVER_ERROR,
)

templates = Jinja2Templates(directory="html/jinja2")


async def invalid_client_exception_handler(request: Request, _: InvalidClientException):
    redirect_uri = request.query_params["redirect_uri"]
    state = request.query_params["state"]
    client_id = request.query_params["client_id"]
    error = UNAUTHORIZED_CLIENT
    error_description = f"OIDC client with client id {client_id} does not exist."
    redirect_uri = f"{redirect_uri}?error={error}&error_description={error_description}&state={state}"
    return templates.TemplateResponse(
        "exception.html",
        {
            "request": request,
            "exception_title": error,
            "exception_message": error_description,
            "redirect_uri": redirect_uri,
        },
    )


async def invalid_redirect_uri_exception_handler(
    request: Request, _: InvalidRedirectUriException
):
    redirect_uri = request.query_params["redirect_uri"]
    state = request.query_params["state"]
    error = UNAUTHORIZED_CLIENT
    error_description = f"Redirect URL {redirect_uri} is not configured."
    redirect_uri = f"{redirect_uri}?error={error}&error_description={error_description}&state={state}"
    return templates.TemplateResponse(
        "exception.html",
        {
            "request": request,
            "exception_title": error,
            "exception_message": error_description,
            "redirect_uri": redirect_uri,
        },
    )


async def server_error_exception_handler(request: Request, _: ServerErrorException):
    redirect_uri = request.query_params["redirect_uri"]
    state = request.query_params["state"]
    error = SERVER_ERROR
    error_description = f"Redirect URL {redirect_uri} is not configured."
    redirect_uri = f"{redirect_uri}?error={error}&error_description={error_description}&state={state}"
    return templates.TemplateResponse(
        "exception.html",
        {
            "request": request,
            "exception_title": error,
            "exception_message": error_description,
            "redirect_uri": redirect_uri,
        },
    )
