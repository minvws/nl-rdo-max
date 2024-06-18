import base64
import json
import logging
import uuid
from typing import Union
from urllib import parse

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from starlette.background import BackgroundTask
from starlette.responses import HTMLResponse, RedirectResponse
from jinja2 import Template

from app.exceptions.max_exceptions import (
    AuthorizationByProxyDisabled,
    UnexpectedAuthnBinding,
)
from app.misc.utils import load_template
from app.models.authorize_response import AuthorizeResponse
from app.models.saml.exceptions import ScopingAttributesNotAllowed
from app.services.vite_manifest_service import ViteManifestService

log = logging.getLogger(__package__)


class SamlResponseFactory:
    def __init__(
        self,
        html_templates_path: str,
        saml_base_issuer: str,
        oidc_authorize_endpoint: str,
        vite_manifest_service: ViteManifestService,
    ):
        self._saml_base_issuer = saml_base_issuer
        self._oidc_authorize_endpoint = oidc_authorize_endpoint

        self._authn_request_template = load_template(
            html_templates_path, "authn_request.html"
        )
        self._vite_manifest_service = vite_manifest_service

    def create_saml_response(
        self, saml_identity_provider, authorize_request, randstate
    ) -> AuthorizeResponse:
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
            f"configured in idp metadata: {saml_identity_provider.name}"
        )

    def _create_saml_authn_submit_response(
        self,
        saml_identity_provider,
        authorize_request,
        randstate,
        status_code: int = 200,
        headers: Union[dict, None] = None,
        media_type: Union[str, None] = None,
        background: Union[BackgroundTask, None] = None,
    ) -> AuthorizeResponse:
        try:
            authn_request = saml_identity_provider.create_authn_request(
                authorize_request.authorization_by_proxy
            )
        except ScopingAttributesNotAllowed as scoping_not_allowed:
            raise AuthorizationByProxyDisabled() from scoping_not_allowed
        template = Template(self._authn_request_template)
        rendered = template.render(
            {
                "sso_url": authn_request.sso_url,
                "saml_request": authn_request.get_base64_string().decode(),
                "relay_state": randstate,
                "vite_asset": self._vite_manifest_service.get_asset_url,
            }
        )
        # pylint: disable=duplicate-code
        return AuthorizeResponse(
            response=HTMLResponse(
                content=rendered,
                status_code=status_code,
                headers=headers,
                media_type=media_type,
                background=background,
            ),
            session_id=authn_request.session_id,
        )

    def _create_saml_authn_redirect_response(
        self, saml_identity_provider, authorize_request, randstate
    ) -> AuthorizeResponse:
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
            raise AuthorizationByProxyDisabled()

        auth = OneLogin_Saml2_Auth(
            request, custom_base_path=saml_identity_provider.base_dir
        )
        return AuthorizeResponse(
            response=RedirectResponse(
                auth.login(
                    return_to=randstate,
                    force_authn=False,
                    set_nameid_policy=False,
                )
            ),
            session_id=auth.get_last_request_id(),
        )

    def create_saml_mock_response(self, authorize_request, randstate):
        base64_authn_request = base64.urlsafe_b64encode(
            json.dumps(authorize_request.dict()).encode()
        ).decode()
        sso_url = "digid-mock?" + parse.urlencode(
            {
                "state": randstate,
                "idp_name": "mock",
                "authorize_request": base64_authn_request,
            }
        )
        template = Template(self._authn_request_template)
        rendered = template.render(
            {
                "sso_url": sso_url,
                "saml_request": uuid.uuid4(),
                "relay_state": randstate,
                "vite_asset": self._vite_manifest_service.get_asset_url,
            }
        )
        return HTMLResponse(content=rendered, status_code=200)
