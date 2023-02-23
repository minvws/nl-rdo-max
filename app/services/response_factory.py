import logging
import os
from typing import Union

from starlette.background import BackgroundTask
from starlette.responses import HTMLResponse

from jinja2 import Template

from app.misc.utils import load_template

log = logging.getLogger(__package__)


class ResponseFactory:
    def __init__(self):
        self._redirect_template = load_template("jinja2", "redirect.html")

    def create_saml_meta_redirect_response(
        self,
        redirect_url: str,
        status_code: int = 200,
        headers: Union[dict, None] = None,
        media_type: Union[str, None] = None,
        background: Union[BackgroundTask, None] = None,
    ):
        template = Template(self._redirect_template)
        rendered = template.render({"redirect_url": redirect_url})

        return HTMLResponse(
            content=rendered,
            status_code=status_code,
            headers=headers,
            media_type=media_type,
            background=background,
        )
