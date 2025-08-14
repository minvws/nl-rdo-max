from typing import Dict, Any, Union

from app.exceptions.max_exceptions import UnauthorizedError
from app.misc.rate_limiter import RateLimiter
from app.models.login_method import LoginMethod
from app.models.login_method_type import LoginMethodType

from app.services.external_session_service import ExternalSessionService
from app.services.loginhandler.authentication_handler import AuthenticationHandler
from app.services.loginhandler.exchange_based_authentication_handler import (
    ExchangeBasedAuthenticationHandler,
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
from app.services.loginhandler.yivi_authentication_handler import (
    YiviAuthenticationHandler,
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
        response_factory: ResponseFactory,
        clients: Dict[str, Any],
        config: Any,
        external_session_service: ExternalSessionService | None = None,
    ):
        self._rate_limiter = rate_limiter
        self._saml_identity_provider_service = saml_identity_provider_service
        self._authentication_cache = authentication_cache
        self._saml_response_factory = saml_response_factory
        self._userinfo_service = userinfo_service
        self._response_factory = response_factory
        self._clients = clients
        self._config = config
        self._saml_authentication_handler: SamlAuthenticationHandler | None = None
        self._mock_saml_authentication_handler: MockSamlAuthenticationHandler | None = (
            None
        )
        self._yivi_authentication_handler: YiviAuthenticationHandler | None = None
        self._uzi_authentication_handler: UziAuthenticationHandler | None = None
        self._oidc_authentication_handler: OidcAuthenticationHandler | None = None
        self._external_session_service: ExternalSessionService | None = (
            external_session_service
        )

    def create(
        self, login_method: LoginMethod
    ) -> Union[AuthenticationHandler, ExchangeBasedAuthenticationHandler]:
        if login_method.type == LoginMethodType.SPECIFIC:
            if login_method.name == "digid":
                return self.create_saml_authentication_handler()
            if login_method.name == "eherkenning_mock":
                return self.create_mock_saml_authentication_handler()
            if login_method.name == "digid_mock":
                return self.create_mock_saml_authentication_handler()
            if login_method.name == "yivi":
                return self.create_yivi_authentication_handler()
            if login_method.name == "uzipas":
                return self.create_uzi_authentication_handler()
        if login_method.type == LoginMethodType.OIDC:
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

    def create_yivi_authentication_handler(self) -> YiviAuthenticationHandler:
        if self._yivi_authentication_handler is None:
            self._yivi_authentication_handler = YiviAuthenticationHandler(
                response_factory=self._response_factory,
                yivi_login_redirect_url=self._config["yivi"]["yivi_login_redirect_url"],
                clients=self._clients,
                external_session_service=self._get_external_session_service(),
            )
        return self._yivi_authentication_handler

    def create_uzi_authentication_handler(self) -> UziAuthenticationHandler:
        if self._uzi_authentication_handler is None:
            self._uzi_authentication_handler = UziAuthenticationHandler(
                response_factory=self._response_factory,
                external_session_service=self._get_external_session_service(),
                uzi_login_redirect_url=self._config["uzi"]["uzi_login_redirect_url"],
                clients=self._clients,
            )
        return self._uzi_authentication_handler

    def create_oidc_authentication_handler(self) -> OidcAuthenticationHandler:
        if self._oidc_authentication_handler is None:
            self._oidc_authentication_handler = OidcAuthenticationHandler(
                response_factory=self._response_factory,
                oidc_login_redirect_url=self._config["oidc_client"][
                    "oidc_login_redirect_url"
                ],
                clients=self._clients,
                external_session_service=self._get_external_session_service(),
            )
        return self._oidc_authentication_handler

    def _get_external_session_service(
        self,
    ) -> ExternalSessionService:
        if self._external_session_service is None:
            raise RuntimeError(
                "External session service is not configured but login method is enabled."
            )
        return self._external_session_service
