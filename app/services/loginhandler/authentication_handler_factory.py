from typing import Dict, Any, Union

from app.exceptions.max_exceptions import UnauthorizedError
from app.misc.rate_limiter import RateLimiter
from app.services.encryption.jwe_service_provider import JweServiceProvider
from app.services.loginhandler.authentication_handler import AuthenticationHandler

from app.services.loginhandler.mock_saml_authentication_handler import (
    MockSamlAuthenticationHandler,
)
from app.services.loginhandler.oidc_authentication_handler import (
    OidcAuthenticationHandler,
)
from app.services.loginhandler.saml_authentication_handler import (
    SamlAuthenticationHandler,
)
from app.services.loginhandler.irma_authentication_handler import (
    IrmaAuthenticationHandler,
)
from app.services.loginhandler.uzi_authentication_handler import (
    UziAuthenticationHandler,
)
from app.services.response_factory import ResponseFactory
from app.services.saml.saml_identity_provider_service import SamlIdentityProviderService
from app.services.saml.saml_response_factory import SamlResponseFactory
from app.services.userinfo.userinfo_service import UserinfoService
from app.storage.authentication_cache import AuthenticationCache


class AuthenticationHandlerFactory:
    # pylint: disable=too-many-instance-attributes
    def __init__(
        self,
        rate_limiter: RateLimiter,
        saml_identity_provider_service: SamlIdentityProviderService,
        authentication_cache: AuthenticationCache,
        saml_response_factory: SamlResponseFactory,
        userinfo_service: UserinfoService,
        jwe_service_provider: JweServiceProvider,
        response_factory: ResponseFactory,
        clients: Dict[str, Any],
        config: Any,
    ):
        self._rate_limiter = rate_limiter
        self._saml_identity_provider_service = saml_identity_provider_service
        self._authentication_cache = authentication_cache
        self._saml_response_factory = saml_response_factory
        self._userinfo_service = userinfo_service
        self._jwe_service_provider = jwe_service_provider
        self._response_factory = response_factory
        self._clients = clients
        self._config = config
        self._saml_authentication_handler: Union[SamlAuthenticationHandler, None] = None
        self._mock_saml_authentication_handler: Union[
            MockSamlAuthenticationHandler, None
        ] = None
        self._irma_authentication_handler: Union[IrmaAuthenticationHandler, None] = None
        self._uzi_authentication_handler: Union[UziAuthenticationHandler, None] = None
        self._oidc_authentication_handler: Union[OidcAuthenticationHandler, None] = None

    def create(self, authentication_method: Dict[str, str]) -> AuthenticationHandler:
        if authentication_method["type"] == "specific":
            if authentication_method["name"] == "digid":
                return self.create_saml_authentication_handler()
            if authentication_method["name"] == "digid_mock":
                return self.create_mock_saml_authentication_handler()
            if authentication_method["name"] == "yivi":
                return self.create_irma_authentication_handler()
            if authentication_method["name"] == "uzipas":
                return self.create_uzi_authentication_handler()
        if authentication_method["type"] == "oidc":
            return self.create_oidc_authentication_handler()
        raise UnauthorizedError(error_description="unknown authentication method")

    def create_saml_authentication_handler(self) -> SamlAuthenticationHandler:
        if self._saml_authentication_handler is None:
            self._saml_authentication_handler = SamlAuthenticationHandler(
                rate_limiter=self._rate_limiter,
                saml_identity_provider_service=self._saml_identity_provider_service,
                authentication_cache=self._authentication_cache,
                saml_response_factory=self._saml_response_factory,
                userinfo_service=self._userinfo_service,
            )
        return self._saml_authentication_handler

    def create_mock_saml_authentication_handler(self) -> MockSamlAuthenticationHandler:
        if self._mock_saml_authentication_handler is None:
            self._mock_saml_authentication_handler = MockSamlAuthenticationHandler(
                rate_limiter=self._rate_limiter,
                saml_identity_provider_service=self._saml_identity_provider_service,
                authentication_cache=self._authentication_cache,
                saml_response_factory=self._saml_response_factory,
                userinfo_service=self._userinfo_service,
            )
        return self._mock_saml_authentication_handler

    def create_irma_authentication_handler(self) -> IrmaAuthenticationHandler:
        if self._irma_authentication_handler is None:
            self._irma_authentication_handler = IrmaAuthenticationHandler(
                jwe_service_provider=self._jwe_service_provider,
                response_factory=self._response_factory,
                session_url=self._config["app"]["session_url"],
                irma_login_redirect_url=self._config["irma"]["irma_login_redirect_url"],
                clients=self._clients,
                session_jwt_issuer=self._config["jwt"]["session_jwt_issuer"],
                session_jwt_audience=self._config["jwt"]["session_jwt_audience"],
                jwt_sign_priv_key_path=self._config["jwt"][
                    "session_jwt_sign_priv_key_path"
                ],
                jwt_sign_crt_path=self._config["jwt"]["session_jwt_sign_crt_path"],
                external_http_requests_timeout_seconds=int(
                    self._config["app"]["external_http_requests_timeout_seconds"]
                ),
            )
        return self._irma_authentication_handler

    def create_uzi_authentication_handler(self) -> UziAuthenticationHandler:
        if self._uzi_authentication_handler is None:
            self._uzi_authentication_handler = UziAuthenticationHandler(
                jwe_service_provider=self._jwe_service_provider,
                response_factory=self._response_factory,
                session_url=self._config["app"]["session_url"],
                uzi_login_redirect_url=self._config["uzi"]["uzi_login_redirect_url"],
                clients=self._clients,
                session_jwt_issuer=self._config["jwt"]["session_jwt_issuer"],
                session_jwt_audience=self._config["jwt"]["session_jwt_audience"],
                jwt_sign_priv_key_path=self._config["jwt"][
                    "session_jwt_sign_priv_key_path"
                ],
                jwt_sign_crt_path=self._config["jwt"]["session_jwt_sign_crt_path"],
                external_http_requests_timeout_seconds=int(
                    self._config["app"]["external_http_requests_timeout_seconds"]
                ),
            )
        return self._uzi_authentication_handler

    def create_oidc_authentication_handler(self) -> OidcAuthenticationHandler:
        if self._oidc_authentication_handler is None:
            self._oidc_authentication_handler = OidcAuthenticationHandler(
                jwe_service_provider=self._jwe_service_provider,
                response_factory=self._response_factory,
                session_url=self._config["app"]["session_url"],
                oidc_login_redirect_url=self._config["oidc_client"][
                    "oidc_login_redirect_url"
                ],
                clients=self._clients,
                session_jwt_issuer=self._config["jwt"]["session_jwt_issuer"],
                session_jwt_audience=self._config["jwt"]["session_jwt_audience"],
                jwt_sign_priv_key_path=self._config["jwt"][
                    "session_jwt_sign_priv_key_path"
                ],
                jwt_sign_crt_path=self._config["jwt"]["session_jwt_sign_crt_path"],
                external_http_requests_timeout_seconds=int(
                    self._config["app"]["external_http_requests_timeout_seconds"]
                ),
            )
        return self._oidc_authentication_handler
