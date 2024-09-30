import unittest
from unittest.mock import MagicMock

from app.exceptions.max_exceptions import UnauthorizedError
from app.models.login_method import LoginMethod
from app.models.login_method_type import LoginMethodType
from app.services.loginhandler.authentication_handler_factory import (
    AuthenticationHandlerFactory,
)
from app.services.loginhandler.mock_saml_authentication_handler import (
    MockSamlAuthenticationHandler,
)
from app.services.loginhandler.oidc_authentication_handler import (
    OidcAuthenticationHandler,
)
from app.services.loginhandler.saml_authentication_handler import (
    SamlAuthenticationHandler,
)
from app.services.loginhandler.uzi_authentication_handler import (
    UziAuthenticationHandler,
)
from app.services.loginhandler.yivi_authentication_handler import (
    YiviAuthenticationHandler,
)


class TestAuthenticationHandlerFactory(unittest.TestCase):
    def setUp(self):
        self.jwt_service_factory = MagicMock()
        self.rate_limiter = MagicMock()
        self.saml_identity_provider_service = MagicMock()
        self.authentication_cache = MagicMock()
        self.saml_response_factory = MagicMock()
        self.userinfo_service = MagicMock()
        self.response_factory = MagicMock()
        self.clients = {}
        self.config = {
            "jwt": {
                "session_jwt_sign_priv_key_path": "path/to/private/key",
                "session_jwt_sign_crt_path": "path/to/cert",
                "session_jwt_issuer": "issuer",
                "session_jwt_audience": "audience",
            },
            "app": {
                "session_url": "http://session.url",
                "external_http_requests_timeout_seconds": 30,
            },
            "yivi": {"yivi_login_redirect_url": "http://yivi.redirect.url"},
            "uzi": {"uzi_login_redirect_url": "http://uzi.redirect.url"},
            "oidc_client": {"oidc_login_redirect_url": "http://oidc.redirect.url"},
        }
        self.factory = AuthenticationHandlerFactory(
            jwt_service_factory=self.jwt_service_factory,
            rate_limiter=self.rate_limiter,
            saml_identity_provider_service=self.saml_identity_provider_service,
            authentication_cache=self.authentication_cache,
            saml_response_factory=self.saml_response_factory,
            userinfo_service=self.userinfo_service,
            response_factory=self.response_factory,
            clients=self.clients,
            config=self.config,
        )

    def test_create_saml_authentication_handler(self):
        login_method = LoginMethod(name="digid", type=LoginMethodType.SPECIFIC)
        handler = self.factory.create(login_method)
        self.assertIsInstance(handler, SamlAuthenticationHandler)

    def test_create_mock_saml_authentication_handler(self):
        login_method = LoginMethod(name="digid_mock", type=LoginMethodType.SPECIFIC)
        handler = self.factory.create(login_method)
        self.assertIsInstance(handler, MockSamlAuthenticationHandler)

    def test_create_yivi_authentication_handler(self):
        login_method = LoginMethod(name="yivi", type=LoginMethodType.SPECIFIC)
        handler = self.factory.create(login_method)
        self.assertIsInstance(handler, YiviAuthenticationHandler)

    def test_create_uzi_authentication_handler(self):
        login_method = LoginMethod(name="uzipas", type=LoginMethodType.SPECIFIC)
        handler = self.factory.create(login_method)
        self.assertIsInstance(handler, UziAuthenticationHandler)

    def test_create_oidc_authentication_handler(self):
        login_method = LoginMethod(name="oidc_provider_a", type=LoginMethodType.OIDC)
        handler = self.factory.create(login_method)
        self.assertIsInstance(handler, OidcAuthenticationHandler)

    def test_create_unauthorized_error(self):
        login_method = LoginMethod(name="unknown", type=LoginMethodType.SPECIFIC)
        with self.assertRaises(UnauthorizedError, msg="unknown authentication method"):
            self.factory.create(login_method)
