from calendar import c
from configparser import ConfigParser
from typing import Any, Container, Dict

import inject
from dependency_injector import providers

from app.dependency_injection.container import Container as MaxContainer

from .bindings import configure_bindings
from .config.schemas import Config
from .services.userinfo.vad_userinfo_service import VadUserinfoService
from .utils import root_path
from .version.models import VersionInfo


# def uvicorn_kwargs() -> dict[str, Any]:
#     config = get_config(root_path("max.conf"))

#     kwargs: dict[str, Any] = {
#         "host": config.get("uvicorn", "host"),
#         "port": config.getint("uvicorn", "port"),
#         "reload": config.getboolean("uvicorn", "reload"),
#         "proxy_headers": True,
#         "workers": config.getint("uvicorn", "workers"),
#     }

#     reload_includes = config.get("uvicorn", "reload_includes", fallback=None)
#     if reload_includes:
#         kwargs["reload_includes"] = reload_includes.split(",")

#     if config.getboolean("uvicorn", "use_ssl"):
#         base_dir = config.get("uvicorn", "base_dir")
#         kwargs["ssl_keyfile"] = f"{base_dir}/{config.get('uvicorn', 'key_file')}"
#         kwargs["ssl_certfile"] = f"{base_dir}/{config.get('uvicorn', 'cert_file')}"

#     return kwargs

def init_module(container: MaxContainer) -> None:
    if not inject.is_configured():
        inject.configure(lambda binder: configure_bindings(binder=binder, config_file="app/vad/vad.conf"))

    # version_info: VersionInfo = inject.instance(VersionInfo)
    # config: Config = inject.instance(Config)
    
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
    userinfo_providers['vad'] = vad_userinfo_service
    
    userinfo_service = providers.Selector(
        selector=max_container.config.app.userinfo_service,
        **userinfo_providers
    )
    
    max_container.services.userinfo_service.override(userinfo_service)

