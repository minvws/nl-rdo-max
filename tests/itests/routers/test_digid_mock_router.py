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
# def digid_mocked_router():
#     digid_mock_app = FastAPI()
#     digid_mock_app.include_router(digid_mock_router)
#     digid_mock_app.container =
#     TestClient(digid_mock_app)
