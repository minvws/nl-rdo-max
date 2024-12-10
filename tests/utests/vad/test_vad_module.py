import os

from fastapi import Depends, FastAPI
import inject
from pydantic import InstanceOf
import pytest
from pytest_mock import MockerFixture

from app.vad.module import init_module as init_vad_module
from app.services.userinfo.cibg_userinfo_service import CIBGUserinfoService
from app.vad.config.services import ConfigParser
from app.vad.utils import root_path
from tests.utests.vad.utils import clear_bindings, configure_bindings
from app.dependency_injection.container import Container as MaxContainer


def test_init_vad_parses_vad_config(mocker: MockerFixture) -> None:
    clear_bindings()

    config_path = root_path("vad.conf")
    if not os.path.isfile(config_path):
        pytest.fail(f"This test requires config file {config_path} to exist")

    inject_configure_spy = mocker.spy(inject, "configure")
    config_parser_init_spy = mocker.spy(ConfigParser, "__init__")

    max_container = MaxContainer()

    init_vad_module(max_container)

    inject_configure_spy.assert_called()
    config_parser_init_spy.assert_called_once_with(
        mocker.ANY,
        mocker.ANY,
        root_path("vad.conf"),
    )


# def test_create_app_does_not_reconfigure_inject(mocker: MockerFixture) -> None:
#     configure_bindings()
#     inject_configure_spy = mocker.spy(inject, "configure")
#     create_app()
#     inject_configure_spy.assert_not_called()
