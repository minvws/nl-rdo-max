"""
Utilities creating strings to be returned to a user or endpoint.

Required:
    - settings.saml.authn_request_html_template
    - Template in location 'saml/templates/html/assertion_consumer_service.html'
"""

from typing import Text, Tuple
from jinja2 import Template
from .config import get_settings

from .saml import AuthNRequest


def _fill_template(template_txt: str, context: dict):
    template = Template(template_txt)
    rendered = template.render(context)

    return rendered


def _fill_template_from_file(filename: str, context: dict) -> Text:
    with open(filename, 'r', encoding='utf-8') as template_file:
        template_txt = template_file.read()

    return _fill_template(template_txt, context)


def create_post_autosubmit_form(context: dict) -> Text:
    return _fill_template_from_file(get_settings().saml.authn_request_html_template, context)


def create_acs_redirect_link(context: dict) -> Text:
    return _fill_template_from_file("saml/templates/html/assertion_consumer_service.html", context)


def create_page_too_busy(page_template_head: str, page_template_tail: str, base_url: str) -> Text:
    return page_template_head + base_url + page_template_tail


def create_authn_post_context(
    relay_state: str,
    url: str,
    issuer_id: str,
    keypair: Tuple[str, str]
) -> dict:
    saml_request = AuthNRequest(url, issuer_id, keypair)
    return {
        'sso_url': url,
        'saml_request': saml_request.get_base64_string().decode(),
        'relay_state': relay_state
    }
