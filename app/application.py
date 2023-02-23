# pylint: disable=c-extension-no-member, too-few-public-methods
import logging
from configparser import ConfigParser
from typing import Type, Union, Callable, Tuple, List

import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

import app.dependency_injection.container
from app.dependency_injection.config import get_config
from app.dependency_injection.container import Container
from app.exceptions.oidc_exception_handlers import general_exception_handler
from app.routers.digid_mock_router import digid_mock_router
from app.routers.oidc_router import oidc_router
from app.routers.saml_router import saml_router
from app.routers.irma_router import irma_router


_exception_handlers: List[Tuple[Union[int, Type[Exception]], Callable]] = [
    (Exception, general_exception_handler),
]


def kwargs_from_config():
    config = get_config()

    kwargs = {
        "host": config.get("uvicorn", "host"),
        "port": config.getint("uvicorn", "port"),
        "reload": config.getboolean("uvicorn", "reload"),
        "proxy_headers": True,
        "workers": config.getint("uvicorn", "workers"),
    }
    if config.getboolean("uvicorn", "use_ssl"):
        kwargs["ssl_keyfile"] = (
            config.get("uvicorn", "base_dir") + "/" + config.get("uvicorn", "key_file")
        )
        kwargs["ssl_certfile"] = (
            config.get("uvicorn", "base_dir") + "/" + config.get("uvicorn", "cert_file")
        )
    return kwargs


def _add_exception_handlers(fastapi: FastAPI):
    for tup in _exception_handlers:
        fastapi.add_exception_handler(tup[0], tup[1])


def run():
    uvicorn.run("app.application:create_fastapi_app", **kwargs_from_config())


def create_fastapi_app(
    config: Union[ConfigParser, None] = None, container: Union[Container, None] = None
) -> FastAPI:
    container = container if container is not None else Container()
    _config: ConfigParser = config if config is not None else get_config()
    loglevel = logging.getLevelName(_config.get("app", "loglevel").upper())

    if isinstance(loglevel, str):
        raise ValueError(f"Invalid loglevel {loglevel.upper()}")
    logging.basicConfig(
        level=loglevel,
        datefmt="%m/%d/%Y %I:%M:%S %p",
    )

    modules=[
        "app.routers.saml_router",
        "app.routers.oidc_router",
        "app.routers.digid_mock_router",
        "app.exceptions.oidc_exception_handlers",
    ]
    container.config.from_dict(dict(_config))
    is_uvicorn_app = _config.getboolean("app", "uvicorn", fallback=False)
    is_production = _config.get("app", "environment").startswith("production")
    irma_enabled = "irma" in _config.get("app", "login_methods").split(", ")
    fastapi = (
        FastAPI(docs_url="/ui", redoc_url="/docs") if is_uvicorn_app else FastAPI()
    )
    fastapi.include_router(saml_router)
    fastapi.include_router(oidc_router)
    if not is_production:
        fastapi.include_router(digid_mock_router)
    if irma_enabled:
        fastapi.include_router(irma_router)
        modules.append("app.routers.irma_router")
    fastapi.mount("/static", StaticFiles(directory="static"), name="static")
    container.wire(
        modules=modules
    )
    fastapi.container = container  # type: ignore
    app.dependency_injection.container._container = (  # pylint: disable=protected-access
        container
    )
    _add_exception_handlers(fastapi)
    return fastapi
