import json

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from app.exceptions.max_exceptions import (
    JsonBaseException,
    TemplateBaseException, RedirectBaseException, ServerErrorException,
)

templates = Jinja2Templates(directory="jinja2")


def base_exception_handler(request: Request, redirect_uri, base_exception: RedirectBaseException):
    # todo: Add human readable error link to this redirect_uri (configurable)
    context = {
        "request": request,
        "exception_title": base_exception.error,
        "exception_message": base_exception.error_description,
    }
    if redirect_uri is not None:
        context["redirect_uri"] = redirect_uri

    return templates.TemplateResponse(
        "exception.html",
        context
    )


async def validation_exception_handler(request: Request, request_validation_error: RequestValidationError):
    exception_message = f"some required arguments are missing: {json.dumps(request_validation_error.errors())}"
    context = {
        "request": request,
        "exception_title": "Invalid request",
        "exception_message": exception_message
    }
    if "redirect_uri" in request.query_params:
        context["redirect_uri"] = request.query_params[
                                      "redirect_uri"] + f"?error=invalid_request&error_message={exception_message}"
    return templates.TemplateResponse(
        "exception.html",
        context
    )


async def general_exception_handler(request: Request, _: Exception):
    redirect_uri = None
    if "redirect_uri" in request.query_params:
        redirect_uri = request.query_params["redirect_uri"]
    return base_exception_handler(
        request,
        redirect_uri,
        ServerErrorException(error_description="Server error", redirect_uri=redirect_uri)
    )


async def template_base_exception_handler(request: Request, json_base_exception: TemplateBaseException):
    redirect_uri = json_base_exception.redirect_uri
    if redirect_uri is None and "redirect_uri" in request.query_params:
        redirect_uri = request.query_params["redirect_uri"]
    return base_exception_handler(request, redirect_uri, json_base_exception)


async def json_base_exception_handler(request: Request, json_base_exception: JsonBaseException):
    redirect_uri = json_base_exception.redirect_uri

    if redirect_uri is None and "redirect_uri" in request.query_params:
        redirect_uri = request.query_params["redirect_uri"]
    if redirect_uri is None:
        return base_exception_handler(request, redirect_uri, json_base_exception)
    return RedirectResponse(
        f"{redirect_uri}?error={json_base_exception.error}&error_description={json_base_exception.error_description}"
    )
