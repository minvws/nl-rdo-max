import base64
import json
import logging
import urllib.parse
from typing import Dict, Mapping, Union, Tuple, Optional

from dependency_injector.wiring import inject, Provide
from fastapi import Request, Depends
from fastapi.exceptions import RequestValidationError
from fastapi.responses import RedirectResponse, Response
from starlette.responses import JSONResponse


from app.dependency_injection.container import Container
from app.exceptions.max_exceptions import (
    OIDCBaseException,
)
from app.misc.utils import translate
from app.services.template_service import TemplateService
from app.models.enums import RedirectType

log = logging.getLogger(__name__)


@inject
def _base_exception_handler(
    request: Request,
    error: str,
    error_description: str,
    redirect_uri: Union[str, None] = None,
    redirect_html_delay: int = 0,
    status_code: int = 500,
    template_service: TemplateService = Depends(Provide["services.template_service"]),
    language_map: Dict[str, str] = Provide[Container.services.language_map],
):
    context = {
        "request": request,
        "exception_title": error,
        "exception_message": error_description,
        "redirect_delay": redirect_html_delay,
        "status_code": status_code,
        "redirect_message": translate(
            "You will automatically be redirected in {{ redirect_delay }} seconds",
            language_map,
        ),
        "error_code": translate("Error code: ", language_map),
        "continue": translate("Continue", language_map),
    }
    if redirect_uri is not None:
        context["redirect_uri"] = redirect_uri
    return template_service.templates.TemplateResponse(
        "exception.html", status_code=status_code, context=context
    )


def client_and_redirect_uri(
    input_dict: Mapping, clients: Dict[str, Dict]
) -> Tuple[Union[str, None], Union[str, None]]:
    client_id = input_dict.get("client_id")
    redirect_uri = input_dict.get("redirect_uri")
    if (
        redirect_uri is None
        or client_id is None
        or client_id not in clients
        or redirect_uri not in clients[client_id]["redirect_uris"]
    ):
        return None, None
    return redirect_uri, client_id


def extract_client_and_redirect_from_state_if_present(
    request: Request, clients: Dict[str, Dict]
) -> Tuple[Union[str, None], Union[str, None]]:
    redirect_uri, client_id = None, None
    try:
        redirect_uri, client_id = client_and_redirect_uri(request.query_params, clients)
        if redirect_uri is None:
            state_key = (
                "RelayState" if "RelayState" in request.query_params else "state"
            )
            if state_key in request.query_params:
                state = json.loads(
                    base64.urlsafe_b64decode(request.query_params[state_key])
                )
                redirect_uri, client_id = client_and_redirect_uri(state, clients)
    except Exception as input_handling_exception:  # pylint: disable=broad-except
        if log.isEnabledFor(logging.DEBUG):
            log.exception(input_handling_exception)
    return redirect_uri, client_id


@inject
def handle_html_exception(
    request: Request,
    error: str,
    error_description: str,
    status_code: int,
    redirect_html_delay: int = Provide[Container.services.redirect_html_delay],
    redirect_type: RedirectType = Provide[Container.services.redirect_type],
    clients: Dict[str, Dict] = Provide[Container.pyop_services.clients],
):
    redirect_uri, client_id = extract_client_and_redirect_from_state_if_present(
        request, clients
    )

    redirect_uri_append_symbol = (
        "&" if redirect_uri is not None and "?" in redirect_uri else "?"
    )

    redirect_uri_with_error = (
        f"{redirect_uri}{redirect_uri_append_symbol}error={error}&error_description={urllib.parse.quote(error_description)}"
        if redirect_uri is not None
        else None
    )
    if (
        redirect_uri is None
        or client_id is None
        or redirect_uri_with_error is None
        or redirect_type == RedirectType.HTML
        or redirect_uri not in clients.get(client_id, {}).get("redirect_uris", [])
    ):
        return _base_exception_handler(
            request,
            error,
            error_description,
            redirect_uri_with_error,
            redirect_html_delay,
            status_code,
        )
    return RedirectResponse(redirect_uri_with_error)


def handle_json_exception(
    error: str,
    error_description: str,
    status_code: int,
):
    return JSONResponse(
        content={"error": error, "error_description": error_description},
        status_code=status_code,
    )


@inject
def handle_exception_redirect(
    request: Request,
    error: str,
    error_description: str,
    log_message: Optional[str],
    language_map: Dict[str, str] = Provide[Container.services.language_map],
    status_code: int = 500,
    include_log_message_in_error_response: bool = Provide[
        Container.services.include_log_message_in_error_response
    ],
) -> Response:
    error_description = translate(error_description, language_map)
    if include_log_message_in_error_response and log_message is not None:
        error_details = translate(log_message, language_map)
        error_description = f"{error_description} ({error_details})"
    if request.headers.get("Accept") == "application/json":
        return handle_json_exception(error, error_description, status_code)
    return handle_html_exception(request, error, error_description, status_code)


@inject
async def general_exception_handler(
    request: Request,
    exception: Exception,
    language_map: Dict[str, str] = Provide[Container.services.language_map],
):
    log_message = None
    if isinstance(exception, OIDCBaseException):
        error = exception.error
        error_description = exception.error_description
        log_message = exception.log_message
        status_code = exception.status_code
    elif isinstance(exception, RequestValidationError):
        errors = exception.errors()
        error_description = translate("The following errors occurred:", language_map)
        missing_params = []
        for error in errors:
            missing_params.append(
                " "
                + translate(error["type"], language_map)  # type: ignore
                + " "
                + error["loc"][1]  # type: ignore
                + " in "
                + error["loc"][0]  # type: ignore
            )

        error = translate("Invalid request", language_map)
        error_description += ",".join(missing_params)
        status_code = 400

    else:
        error = "server_error"
        error_description = "Something went wrong"
        status_code = 500
    return handle_exception_redirect(
        request, error, error_description, log_message, status_code=status_code
    )
