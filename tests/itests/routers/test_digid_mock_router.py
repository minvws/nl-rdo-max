# from unittest.mock import MagicMock
#
# import pytest
# from dependency_injector import containers, providers
# from fastapi import FastAPI
# from fastapi.testclient import TestClient
#
# from app.routers.digid_mock_router import digid_mock_router
#
#
# digid_mock = MagicMock()
#
#
# class OverridingContainer(containers.DeclarativeContainer):
#     digid_mock_provider = providers.Object(digid_mock)
#
#
#
# @pytest.fixture
# def digid_mocked_router(container_overrides):
#     digid_mock_app = FastAPI()
#     digid_mock_app.include_router(digid_mock_router)
#     digid_mock_app.container =
#     TestClient(digid_mock_app)
# @pytest.fixture
# def mocked_digid_provider(container_overrides):
#     def override_digid(container):
#         overiding_container = OverridingContainer()
#         container.services.override(overiding_container)
#
#     def override_pyop(container):
#         pyop = PyopOverridingContainer()
#         if config["app"]["app_mode"] == "legacy":
#             pyop.clients.override(providers.Object(dict([legacy_client])))
#         else:
#             pyop.clients.override(
#                 providers.Object(dict([client]))
#             )  # pylint:disable=c-extension-no-member
#         container.pyop_services.override(pyop)
#
#     container_overrides.append(override_pyop)
