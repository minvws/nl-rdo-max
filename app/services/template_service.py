from typing import Optional

from fastapi.templating import Jinja2Templates

from app.services.vite_manifest_service import ViteManifestService


class TemplateService:
    def __init__(
        self,
        jinja_template_directory: str,
        vite_manifest_service: Optional[ViteManifestService] = None,
    ):
        self.vite_manifest_service = vite_manifest_service

        self._templates = Jinja2Templates(directory=jinja_template_directory)

        if self.vite_manifest_service is not None:
            self._templates.env.globals[
                "vite_asset"
            ] = self.vite_manifest_service.get_asset_url

    @property
    def templates(self) -> Jinja2Templates:
        return self._templates
