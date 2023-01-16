import base64
import json
import logging
import os
from urllib import parse

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from starlette.background import BackgroundTask
from starlette.responses import HTMLResponse, RedirectResponse

from jinja2 import Template

from app.exceptions.max_exceptions import (
    AuthorizationByProxyDisabled,
    UnexpectedAuthnBinding,
)
from app.models.saml.exceptions import ScopingAttributesNotAllowed

log = logging.getLogger(__package__)


def _load_template(path, filename):
    template_path = os.path.join(path, filename)
    with open(template_path, "r", encoding="utf-8") as template_file:
        return template_file.read()


class SamlResponseFactory:
    def __init__(
        self,
        html_templates_path: str,
        saml_base_issuer: str,
        oidc_authorize_endpoint: str,
    ):
        self._saml_base_issuer = saml_base_issuer
        self._oidc_authorize_endpoint = oidc_authorize_endpoint

        self._authn_request_template = _load_template(
            html_templates_path, "authn_request.html"
        )
        self._assertion_consumer_service_template = _load_template(
            html_templates_path, "assertion_consumer_service.html"
        )

    def create_saml_response(
        self, saml_identity_provider, authorize_request, randstate
    ):
        if saml_identity_provider.authn_binding.endswith("POST"):
            return self._create_saml_authn_submit_response(
                saml_identity_provider, authorize_request, randstate
            )
        if saml_identity_provider.authn_binding.endswith("Redirect"):
            return self._create_saml_authn_redirect_response(
                saml_identity_provider, authorize_request, randstate
            )
        raise UnexpectedAuthnBinding(
            error_description=f"Unknown Authn binding {saml_identity_provider.authn_binding} "
            f"configured in idp metadata: {saml_identity_provider.name}",
            redirect_uri=None,
        )

    def create_saml_meta_redirect_response(
        self,
        redirect_url: str,
        status_code: int = 200,
        headers: dict = None,
        media_type: str = None,
        background: BackgroundTask = None,
    ):
        template = Template(self._assertion_consumer_service_template)
        rendered = template.render({"redirect_url": redirect_url})

        return HTMLResponse(
            content=rendered,
            status_code=status_code,
            headers=headers,
            media_type=media_type,
            background=background,
        )

    def _create_saml_authn_submit_response(
        self,
        saml_identity_provider,
        authorize_request,
        randstate,
        status_code: int = 200,
        headers: dict = None,
        media_type: str = None,
        background: BackgroundTask = None,
    ):
        try:
            authn_request = saml_identity_provider.create_authn_request(
                authorize_request.authorization_by_proxy
            )
        except ScopingAttributesNotAllowed as scoping_not_allowed:
            raise AuthorizationByProxyDisabled(
                redirect_uri=None
            ) from scoping_not_allowed
        template = Template(self._authn_request_template)
        rendered = template.render(
            {
                "sso_url": authn_request.sso_url,
                "saml_request": authn_request.get_base64_string().decode(),
                "relay_state": randstate,
            }
        )
        return HTMLResponse(
            content=rendered,
            status_code=status_code,
            headers=headers,
            media_type=media_type,
            background=background,
        )

    def _create_saml_authn_redirect_response(
        self, saml_identity_provider, authorize_request, randstate
    ):
        request = {
            "https": "on",
            "http_host": (
                f"https://{saml_identity_provider.name}.{self._saml_base_issuer}"
            ),
            "script_name": self._oidc_authorize_endpoint,
            "get_data": authorize_request.dict(),
        }
        if authorize_request.authorization_by_proxy:
            log.warning(
                "User attempted to login using authorization by proxy. But is not"
                " supported for this IDProvider: %s",
                saml_identity_provider.name,
            )
            raise AuthorizationByProxyDisabled(redirect_uri=None)

        auth = OneLogin_Saml2_Auth(
            request, custom_base_path=saml_identity_provider.base_dir
        )
        return RedirectResponse(
            auth.login(
                return_to=randstate,
                force_authn=False,
                set_nameid_policy=False,
            )
        )

    def create_saml_mock_response(
        self, saml_identity_provider, authorize_request, randstate
    ):
        base64_authn_request = base64.urlsafe_b64encode(
            json.dumps(authorize_request.dict()).encode()
        ).decode()
        sso_url = "/digid-mock?" + parse.urlencode(
            {
                "state": randstate,
                "idp_name": saml_identity_provider.name,
                "authorize_request": base64_authn_request,
            }
        )
        authn_request = saml_identity_provider.create_authn_request([], [])
        template = Template(self._authn_request_template)
        rendered = template.render(
            {
                "sso_url": sso_url,
                "saml_request": authn_request.get_base64_string().decode(),
                "relay_state": randstate,
            }
        )
        return HTMLResponse(content=rendered, status_code=200)
