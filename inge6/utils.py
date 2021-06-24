from typing import Text
from jinja2 import Template
from .config import settings


def _fill_template(template_txt: str, context: dict):
    template = Template(template_txt)
    rendered = template.render(context)

    return rendered


def _fill_template_from_file(filename: str, context: dict) -> Text:
    with open(filename, 'r') as template_file:
        template_txt = template_file.read()

    return _fill_template(template_txt, context)


def create_post_autosubmit_form(context: dict) -> Text:
    return _fill_template_from_file(settings.saml.authn_request_html_template, context)


def create_page_too_busy(page_template_head: str, page_template_tail: str, base_url: str) -> Text:
    return page_template_head + base_url + page_template_tail
