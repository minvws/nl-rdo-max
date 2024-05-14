import logging
from typing import Union

from fastapi.responses import RedirectResponse
from starlette.background import BackgroundTask
from starlette.responses import HTMLResponse
from jinja2 import Template

from app.misc.utils import load_template
from app.models.enums import RedirectType

log = logging.getLogger(__package__)


class ResponseFactory:
    def __init__(self, redirect_type: RedirectType):
        self._redirect_template = load_template("jinja2", "redirect.html")
        self._redirect_type = redirect_type

    def create_redirect_response(
        self,
        redirect_url: str,
        status_code: int = 200,
        headers: Union[dict, None] = None,
        media_type: Union[str, None] = None,
        background: Union[BackgroundTask, None] = None,
    ):
        if self._redirect_type == RedirectType.HTML:
            template = Template(self._redirect_template)
            rendered = template.render({"redirect_url": redirect_url})

            return HTMLResponse(
                content=rendered,
                status_code=status_code,
                headers=headers,
                media_type=media_type,
                background=background,
            )
        return RedirectResponse(redirect_url)
