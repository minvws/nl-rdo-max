# pylint: disable=c-extension-no-member, too-few-public-methods
from dependency_injector import containers, providers

from app.misc.rate_limiter import RateLimiter
from app.misc.utils import as_bool, json_from_file
from app.services.template_service import TemplateService
from app.services.vite_manifest_service import ViteManifestService
from app.models.enums import RedirectType
from app.providers.digid_mock_provider import DigidMockProvider
from app.providers.oidc_provider import OIDCProvider
from app.providers.saml_provider import SAMLProvider
from app.services.loginhandler.authentication_handler_factory import (
    AuthenticationHandlerFactory,
)
from app.services.saml.saml_identity_provider_service import SamlIdentityProviderService
from app.services.saml.saml_response_factory import SamlResponseFactory
from app.services.response_factory import ResponseFactory
from app.services.userinfo.cc_userinfo_service import CCUserinfoService
from app.services.userinfo.cibg_userinfo_service import (
    CIBGUserinfoService,
)
from app.validators.token_authentication_validator import TokenAuthenticationValidator


def as_redirect_type(value):
    return RedirectType(value)


class Services(containers.DeclarativeContainer):
    config = providers.Configuration()

    encryption_services = providers.DependenciesContainer()

    storage = providers.DependenciesContainer()

    pyop_services = providers.DependenciesContainer()

    redirect_html_delay = config.app.redirect_html_delay

    redirect_type = config.app.redirect_type.as_(as_redirect_type)

    json_schema = providers.Callable(json_from_file, config.app.json_schema_path)

    vite_manifest_service = providers.Singleton(
        ViteManifestService,
        manifest=providers.Callable(
            json_from_file, config.templates.vite_manifest_path
        ),
    )

    language_map = providers.Callable(json_from_file, config.app.language_path)
    include_log_message_in_error_response = (
        config.app.include_log_message_in_error_response.as_(as_bool)
    )

    token_authentication_validator = providers.Singleton(
        TokenAuthenticationValidator,
        oidc_configuration_info=pyop_services.pyop_configuration_information,
    )

    template_service = providers.Singleton(
        TemplateService,
        jinja_template_directory=config.templates.jinja_path,
        vite_manifest_service=vite_manifest_service,
        header_template=config.templates.header_template,
        sidebar_template=config.templates.sidebar_template,
    )

    saml_response_factory = providers.Singleton(
        SamlResponseFactory,
        html_templates_path=config.saml.html_templates_path,
        saml_base_issuer=config.saml.base_issuer,
        oidc_authorize_endpoint=config.oidc.authorize_endpoint,
        vite_manifest_service=vite_manifest_service,
    )

    response_factory = providers.Singleton(ResponseFactory, redirect_type=redirect_type)
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
        external_http_requests_timeout_seconds=config.app.external_http_requests_timeout_seconds.as_int(),
    )

    cibg_userinfo_service = providers.Singleton(
        CIBGUserinfoService,
        jwe_service_provider=encryption_services.jwe_service_provider,
        environment=config.app.environment,
        clients=pyop_services.clients,
        userinfo_request_signing_priv_key_path=config.jwe.jwe_sign_priv_key_path,
        userinfo_request_signing_crt_path=config.jwe.jwe_sign_crt_path,
        ssl_client_key_path=config.cibg.ssl_client_key,
        ssl_client_crt_path=config.cibg.ssl_client_crt,
        ssl_client_verify=config.cibg.ssl_client_verify.as_(as_bool),
        cibg_exchange_token_endpoint=config.cibg.cibg_exchange_token_endpoint,
        cibg_saml_endpoint=config.cibg.cibg_saml_endpoint,
        cibg_userinfo_issuer=config.cibg.userinfo_issuer,
        cibg_userinfo_audience=config.cibg.userinfo_audience,
        req_issuer=config.oidc.issuer,
        jwt_expiration_duration=config.oidc.jwt_expiration_duration.as_int(),
        jwt_nbf_lag=config.oidc.jwt_nbf_lag.as_int(),
        external_http_requests_timeout_seconds=config.app.external_http_requests_timeout_seconds.as_int(),
        external_base_url=config.app.external_base_url,
    )

    cc_userinfo_service = providers.Singleton(
        CCUserinfoService,
        jwe_service_provider=encryption_services.jwe_service_provider,
        clients=pyop_services.clients,
        app_mode=config.app.app_mode,
        req_issuer=config.oidc.issuer,
        jwt_expiration_duration=config.oidc.jwt_expiration_duration.as_int(),
        jwt_nbf_lag=config.oidc.jwt_nbf_lag.as_int(),
    )

    userinfo_service = providers.Selector(
        config.app.userinfo_service,
        cc=cc_userinfo_service,
        cibg=cibg_userinfo_service,
    )

    login_handler_factory = providers.Singleton(
        AuthenticationHandlerFactory,
        rate_limiter=rate_limiter,
        saml_identity_provider_service=saml_identity_provider_service,
        authentication_cache=storage.authentication_cache,
        saml_response_factory=saml_response_factory,
        userinfo_service=userinfo_service,
        jwe_service_provider=encryption_services.jwe_service_provider,
        response_factory=response_factory,
        clients=pyop_services.clients,
        config=config,
    )

    oidc_provider = providers.Singleton(
        OIDCProvider,
        pyop_provider=pyop_services.pyop_provider,
        authentication_cache=storage.authentication_cache,
        rate_limiter=rate_limiter,
        clients=pyop_services.clients,
        saml_response_factory=saml_response_factory,
        response_factory=response_factory,
        userinfo_service=userinfo_service,
        app_mode=config.app.app_mode,
        environment=config.app.environment,
        login_methods=config.app.login_methods_file_path.as_(json_from_file),
        authentication_handler_factory=login_handler_factory,
        external_base_url=config.app.external_base_url,
        external_http_requests_timeout_seconds=config.app.external_http_requests_timeout_seconds.as_int(),
        login_options_sidebar_template=config.templates.login_options_sidebar_template,
        template_service=template_service,
        allow_wildcard_redirect_uri=config.oidc.allow_wildcard_redirect_uri.as_(
            as_bool
        ),
        token_authentication_validator=token_authentication_validator,
    )

    digid_mock_provider = providers.Singleton(
        DigidMockProvider,
        template_service=template_service,
    )

    saml_provider = providers.Singleton(
        SAMLProvider,
        saml_response_factory=saml_response_factory,
        oidc_provider=oidc_provider,
        saml_identity_provider_service=saml_identity_provider_service,
        rate_limiter=rate_limiter,
        userinfo_service=userinfo_service,
        environment=config.app.environment.as_(str.lower),
        clients=pyop_services.clients,
    )
