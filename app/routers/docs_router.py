from fastapi import APIRouter, Request
from fastapi.openapi.docs import (
    get_redoc_html,
    get_swagger_ui_html,
)

from app.models.swagger_config import SwaggerConfig


class DocsRouter:
    _swagger_config: SwaggerConfig

    def __init__(self, swagger_config: SwaggerConfig):
        self._swagger_config = swagger_config

    def get_docs_router(self) -> APIRouter:
        docs_router = APIRouter()

        if (
            self._swagger_config.swagger_ui_endpoint
            and self._swagger_config.openapi_endpoint
        ):
            docs_router.add_route(
                path=self._swagger_config.swagger_ui_endpoint,
                endpoint=self.custom_swagger_ui_html,
                include_in_schema=False,
            )

        if (
            self._swagger_config.redoc_endpoint
            and self._swagger_config.openapi_endpoint
        ):
            docs_router.add_route(
                path=self._swagger_config.redoc_endpoint,
                endpoint=self.redoc_html,
                include_in_schema=False,
            )

        return docs_router

    async def custom_swagger_ui_html(
        self,
        _request: Request,
    ):
        return get_swagger_ui_html(
            openapi_url=self._swagger_config.openapi_endpoint or "",
            title="Swagger UI",
            swagger_js_url="static/assets/swagger-ui-bundle.js",
            swagger_css_url="static/assets/swagger-ui.css",
            swagger_favicon_url="static/img/favicon.ico",
        )

    async def redoc_html(
        self,
        _request: Request,
    ):
        return get_redoc_html(
            openapi_url=self._swagger_config.openapi_endpoint or "",
            title="ReDoc",
            redoc_js_url="static/assets/redoc.standalone.js",
            redoc_favicon_url="static/img/favicon.ico",
            with_google_fonts=False,
        )
