# pylint: disable=c-extension-no-member, too-few-public-methods
from dependency_injector import containers, providers

from app.dependency_injection.storage import Storage
from app.dependency_injection.services import Services
from app.dependency_injection.pyop_services import PyopServices


class Container(containers.DeclarativeContainer):
    config = providers.Configuration()

    providers.Configuration()

    storage = providers.Container(
        Storage,
        config=config,
    )

    pyop_services = providers.Container(
        PyopServices,
        config=config,
        storage=storage
    )

    services = providers.Container(
        Services,
        config=config,
        storage=storage,
        pyop_services=pyop_services
    )
