import inject
from dependency_injector import providers

from app.dependency_injection.container import Container as MaxContainer

from .bindings import configure_bindings
from .services.userinfo.vad_userinfo_service import VadUserinfoService


def init_module(container: MaxContainer) -> None:
    if not inject.is_configured():
        inject.configure(
            lambda binder: configure_bindings(binder=binder, config_file="vad.conf")
        )

    inject_vad_userinfo_service(max_container=container)


def inject_vad_userinfo_service(max_container: MaxContainer) -> None:

    vad_userinfo_service = providers.Singleton(
        VadUserinfoService,
        jwt_service_factory=max_container.encryption_services.jwt_service_factory,
        userinfo_request_signing_priv_key_path=max_container.config.jwe.jwe_sign_priv_key_path,
        userinfo_request_signing_crt_path=max_container.config.jwe.jwe_sign_crt_path,
        req_issuer=max_container.config.oidc.issuer,
        clients=max_container.pyop_services.clients,
    )

    userinfo_providers = max_container.services.userinfo_service.providers.copy()
    userinfo_providers["vad"] = vad_userinfo_service

    userinfo_service = providers.Selector(
        selector=max_container.config.app.userinfo_service, **userinfo_providers
    )

    max_container.services.userinfo_service.override(userinfo_service)
