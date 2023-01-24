import base64
import json
import logging
from typing import Dict, Mapping, Union, Tuple

from dependency_injector.wiring import inject, Provide
from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from app.dependency_injection.container import Container
from app.exceptions.max_exceptions import (
    RedirectBaseException,
)

log = logging.getLogger(__name__)

templates = Jinja2Templates(directory="jinja2")


def _base_exception_handler(
    request: Request,
    error: str,
    error_description: str,
    redirect_uri: Union[str, None] = None,
    redirect_html_delay: int = 0,
):
    context = {
        "request": request,
        "exception_title": error,
        "exception_message": error_description,
        "redirect_delay": redirect_html_delay,
    }
    if redirect_uri is not None:
        context["redirect_uri"] = redirect_uri

    return templates.TemplateResponse("exception.html", context)


def client_and_redirect_uri(
    input_dict: Mapping,
) -> Tuple[Union[str, None], Union[str, None]]:
    return input_dict.get("redirect_uri"), input_dict.get("client_id")


def handle_exception_redirect(
    request: Request,
    clients: Dict[str, Dict],
    error: str,
    error_description: str,
    redirect_html_delay: int,
    redirect_type: str,
) -> Response:
    redirect_uri, client_id = None, None
    try:
        redirect_uri, client_id = client_and_redirect_uri(request.query_params)
        if redirect_uri is None:
            state = json.loads(
                base64.urlsafe_b64decode(request.query_params["RelayState"])
            )
            redirect_uri, client_id = client_and_redirect_uri(state)
    except Exception as input_handling_exception:  # pylint: disable=broad-except
        if log.isEnabledFor(logging.DEBUG):
            log.exception(input_handling_exception)
    redirect_uri_with_error = (
        f"{redirect_uri}?error={error}&error_description={error_description}"
        if redirect_uri is not None
        else None
    )
    if (
        redirect_uri is None
        or client_id is None
        or redirect_uri_with_error is None
        or redirect_type == "html"
        or redirect_uri not in clients.get(client_id, {}).get("redirect_uris", [])
    ):
        return _base_exception_handler(
            request,
            error,
            error_description,
            redirect_uri_with_error,
            redirect_html_delay,
        )
    return RedirectResponse(redirect_uri_with_error)


@inject
async def general_exception_handler(
    request: Request,
    exception: Exception,
    clients: Dict[str, Dict] = Provide[Container.pyop_services.clients],
    redirect_html_delay: int = Provide[Container.services.redirect_html_delay],
    redirect_type: str = Provide[Container.services.redirect_type],
):
    if isinstance(exception, RedirectBaseException):
        error = exception.error
        error_description = exception.error_description
    elif isinstance(exception, RequestValidationError):
        error = "Invalid request"
        error_description = (
            f"some required arguments are missing: {json.dumps(exception.errors())}"
        )
    else:
        error = "server_error"
        error_description = "Something went wrong"
    return handle_exception_redirect(
        request, clients, error, error_description, redirect_html_delay, redirect_type
    )
