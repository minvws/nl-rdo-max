# pylint: disable=c-extension-no-member, too-few-public-methods
from dependency_injector import containers, providers

from app.misc.rate_limiter import RateLimiter
from app.misc.utils import as_bool, as_list
from app.providers.digid_mock_provider import DigidMockProvider
from app.providers.oidc_provider import OIDCProvider
from app.providers.saml_provider import SAMLProvider
from app.services.loginhandler.authentication_handler_factory import (
    AuthenticationHandlerFactory,
)
from app.services.loginhandler.mock_saml_authentication_handler import (
    MockSamlAuthenticationHandler,
)
from app.services.loginhandler.saml_authentication_handler import (
    SamlAuthenticationHandler,
)
from app.services.saml.saml_identity_provider_service import SamlIdentityProviderService
from app.services.saml.saml_response_factory import SamlResponseFactory
from app.services.userinfo.cc_userinfo_service import CCUserinfoService
from app.services.userinfo.cibg_userinfo_service import (
    CIBGUserinfoService,
)
from app.services.userinfo.mock_cibg_userinfo_service import MockedCIBGUserinfoService


class Services(containers.DeclarativeContainer):
    config = providers.Configuration()

    encryption_services = providers.DependenciesContainer()

    storage = providers.DependenciesContainer()

    pyop_services = providers.DependenciesContainer()

    saml_response_factory = providers.Singleton(
        SamlResponseFactory,
        html_templates_path=config.saml.html_templates_path,
        saml_base_issuer=config.saml.base_issuer,
        oidc_authorize_endpoint=config.oidc.authorize_endpoint,
    )

    rate_limiter = providers.Singleton(
        RateLimiter,
        cache=storage.cache,
        identity_provider_outage_key=config.ratelimiter.identity_provider_outage_key,
        primary_identity_provider_key=config.ratelimiter.primary_identity_provider_key,
        overflow_identity_provider_key=config.ratelimiter.overflow_identity_provider_key,
        primary_identity_provider_user_limit_key=config.ratelimiter.primary_identity_provider_user_limit_key,
        overflow_identity_provider_user_limit_key=config.ratelimiter.overflow_identity_provider_user_limit_key,
        ipaddress_max_count=config.ratelimiter.ipaddress_max_count.as_int(),
        ipaddress_max_count_expire_seconds=config.ratelimiter.ipaddress_max_count_expire_seconds.as_int(),
    )

    saml_identity_provider_service = providers.Singleton(
        SamlIdentityProviderService,
        identity_providers_base_path=config.saml.identity_providers_base_path,
        templates_path=config.saml.xml_templates_path,
    )

    cibg_external_user_authentication_service = providers.Singleton(CIBGUserinfoService)

    mocked_cibg_userinfo_service = providers.Singleton(
        MockedCIBGUserinfoService,
        jwe_service=encryption_services.jwe_service,
        clients=pyop_services.clients,
        environment=config.app.environment,
        mock_cibg=config.app.mock_cibg.as_(as_bool),
    )

    cc_userinfo_service = providers.Singleton(
        CCUserinfoService,
        jwe_service=encryption_services.jwe_service,
        clients=pyop_services.clients,
        app_mode=config.app.app_mode,
    )

    userinfo_service = providers.Selector(
        config.app.userinfo_service,
        cc=cc_userinfo_service,
        cibg_mock=mocked_cibg_userinfo_service,
    )

    saml_login_handler = providers.Singleton(
        SamlAuthenticationHandler,
        rate_limiter=rate_limiter,
        saml_identity_provider_service=saml_identity_provider_service,
        authentication_cache=storage.authentication_cache,
        saml_response_factory=saml_response_factory,
        userinfo_service=userinfo_service,
    )

    mock_saml_login_handler = providers.Singleton(
        MockSamlAuthenticationHandler,
        rate_limiter=rate_limiter,
        saml_identity_provider_service=saml_identity_provider_service,
        authentication_cache=storage.authentication_cache,
        saml_response_factory=saml_response_factory,
        userinfo_service=userinfo_service,
    )

    login_handler_factory = providers.Singleton(
        AuthenticationHandlerFactory,
        saml_authentication_handler=saml_login_handler,
        mock_saml_authentication_handler=mock_saml_login_handler,
    )

    oidc_provider = providers.Singleton(
        OIDCProvider,
        pyop_provider=pyop_services.pyop_provider,
        authentication_cache=storage.authentication_cache,
        rate_limiter=rate_limiter,
        clients=pyop_services.clients,
        mock_digid=config.app.mock_digid.as_(as_bool),
        saml_response_factory=saml_response_factory,
        userinfo_service=userinfo_service,
        app_mode=config.app.app_mode,
        environment=config.app.environment,
        login_methods=config.app.login_methods.as_(as_list),
        authentication_handler_factory=login_handler_factory,
    )

    digid_mock_provider = providers.Singleton(
        DigidMockProvider,
        saml_response_factory=saml_response_factory,
        saml_identity_provider_service=saml_identity_provider_service,
        environment=config.app.environment.as_(str.lower),
    )

    saml_provider = providers.Singleton(
        SAMLProvider,
        saml_response_factory=saml_response_factory,
        oidc_provider=oidc_provider,
        saml_identity_provider_service=saml_identity_provider_service,
        rate_limiter=rate_limiter,
        userinfo_service=userinfo_service,
        environment=config.app.environment.as_(str.lower),
    )
