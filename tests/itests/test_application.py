from dependency_injector import providers

from app.application import _parse_origins
from tests.itests.conftest import PyopOverridingContainer


def test_parse_origins(container_overrides, lazy_container):
    def override_pyop(container):
        pyop = PyopOverridingContainer()
        pyop.clients.override(
            providers.Object(
                {
                    "a": {"redirect_uris": ["http://localhost:3000/this/should"]},
                    "b": {"redirect_uris": ["http://localpost:3001/be/ignored.html"]},
                }
            )
        )
        container.pyop_services.override(pyop)

    container_overrides.append(override_pyop)

    origins = _parse_origins(lazy_container.value)

    assert origins == ["http://localhost:3000", "http://localpost:3001"]
