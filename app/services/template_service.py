from typing import Optional

from markupsafe import Markup

from fastapi.templating import Jinja2Templates
from starlette.requests import Request
from starlette.templating import _TemplateResponse
from jinja2 import pass_context, Template

from app.services.vite_manifest_service import ViteManifestService


@pass_context
def evaluate(context, value):
    return Markup(Template(value).render(context))


class TemplateService:
    def __init__(
        self,
        jinja_template_directory: str,
        vite_manifest_service: Optional[ViteManifestService] = None,
        header_template: Optional[str] = None,
        sidebar_template: Optional[str] = None,
    ):
        self.vite_manifest_service = vite_manifest_service

        self._templates = Jinja2Templates(directory=jinja_template_directory)

        self._templates.env.filters["evaluate"] = evaluate

        if self.vite_manifest_service is not None:
            self._templates.env.globals["vite_asset"] = (
                self.vite_manifest_service.get_asset_url
            )

        if header_template is not None and len(header_template) > 0:
            self._templates.env.globals["header"] = header_template

        if sidebar_template is not None and len(sidebar_template) > 0:
            self._templates.env.globals["sidebar"] = sidebar_template

    @property
    def templates(self) -> Jinja2Templates:
        return self._templates

    def render_layout(
        self,
        request: Request,
        template_name: str,
        page_title: str,
        page_context: dict,
        sidebar_template: Optional[str] = None,
    ) -> _TemplateResponse:
        default_context = {
            "request": request,
            "layout": "layout.html",
            "page_title": page_title,
        }

        if sidebar_template is not None and len(sidebar_template) > 0:
            default_context["sidebar"] = sidebar_template

        context = {**default_context, **page_context}
        return self.templates.TemplateResponse(template_name, context)
