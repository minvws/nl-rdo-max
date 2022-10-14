# pylint: disable=c-extension-no-member, too-few-public-methods
from configparser import ConfigParser

from dependency_injector import providers
from fastapi import FastAPI
import uvicorn

from app.dependency_injection.container import Container
from app.dependency_injection.config import get_config
from app.routers.digid_mock_router import digid_mock_router
from app.routers.saml_router import saml_router
from app.routers.oidc_router import oidc_router
from app.routers.cc_router import cc_router
from app.routers.irma_router import irma_router

from app.exceptions.oidc_exceptions import (
    AuthorizeEndpointException,
    InvalidClientException,
    InvalidRedirectUriException,
)

from app.exceptions.oidc_exception_handlers import (
    invalid_client_exception_handler,
    invalid_redirect_uri_exception_handler,
    server_error_exception_handler
)

_exception_handlers = [
    [InvalidClientException, invalid_client_exception_handler]
]


def kwargs_from_config():
    config = get_config()

    kwargs = {
        "host": config.get("uvicorn", "host"),
        "port": config.getint("uvicorn", "port"),
        "reload": config.getboolean("uvicorn", "reload"),
        "proxy_headers": True,
        "workers": config.getint("uvicorn", "workers")
    }
    if config.getboolean("uvicorn", "use_ssl"):
        kwargs["ssl_keyfile"] = config.get("uvicorn", "base_dir") + \
            "/" + config.get("uvicorn", "key_file")
        kwargs["ssl_certfile"] = config.get("uvicorn", "base_dir") + \
            "/" + config.get("uvicorn", "cert_file")
    return kwargs


def _add_exception_handlers(fastapi: FastAPI):
    for tup in _exception_handlers:
        fastapi.add_exception_handler(tup[0], tup[1])


def run():
    uvicorn.run("app.application:create_fastapi_app", **kwargs_from_config())


def create_fastapi_app(
    config: ConfigParser = None,
    container: Container = None
):
    container = container if container is not None else Container()
    config: dict = config if config is not None else get_config()
    container.wire(
        modules=["app.routers.saml_router",
                 "app.routers.oidc_router",
                 "app.routers.cc_router",
                 "app.routers.uzi_router",
                 "app.routers.irma_router",
                 "app.routers.digid_mock_router"
                 ])

    container.config.from_dict(config)
    is_uvicorn_app = config.getboolean("app", "uvicorn", fallback=False)
    cc_routing_enabled = config.getboolean("app", "cc_routing_enabled", fallback=False)
    uzi_routing_enabled = config.getboolean("app", "uzi_routing_enabled", fallback=False)
    is_mock_digid = config.getboolean("app", "mock_digid", fallback=False)
    fastapi_kwargs = {
        "docs_url": "/ui",
        "redoc_url": "/docs"
    } if is_uvicorn_app else {}
    fastapi = FastAPI(**fastapi_kwargs)
    fastapi.include_router(saml_router)
    fastapi.include_router(oidc_router)
    if cc_routing_enabled:
        fastapi.include_router(cc_router)
    # if uzi_routing_enabled:
    #     container.services.override(UziServices)
    if is_mock_digid:
        fastapi.include_router(digid_mock_router)

    fastapi.container = container
    _add_exception_handlers(fastapi)
    return fastapi
