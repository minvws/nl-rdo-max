from configparser import ConfigParser
from typing import Optional, Dict

from starlette.testclient import TestClient

from app.application import create_fastapi_app
from app.dependency_injection.config import get_config


def test_openapi_endpoint_available():
    config = {
        "swagger": {"enabled": "True", "openapi_endpoint": "/openapi.json"},
    }

    app = get_app(override_config=config)
    actual_response = app.get("/openapi.json")

    assert actual_response.status_code == 200

    openapi = actual_response.json()

    assert openapi["info"]["version"] == "v0.0.0"


def test_openapi_endpoint_with_version():
    config = {
        "app": {"version_file_path": "tests/resources/version.json.example"},
        "swagger": {"enabled": "True", "openapi_endpoint": "/openapi.json"},
    }

    app = get_app(override_config=config)
    actual_response = app.get("/openapi.json")

    openapi = actual_response.json()

    assert actual_response.status_code == 200
    assert openapi["info"]["version"] == "v1.2.3"


def test_openapi_endpoint_disabled():
    config = {
        "swagger": {"enabled": "False", "openapi_endpoint": "/openapi.json"},
    }

    app = get_app(override_config=config)
    actual_response = app.get("/openapi.json")

    assert actual_response.status_code == 404


def test_openapi_endpoint_not_available_with_empty_endpoint():
    config = {
        "swagger": {"enabled": "True", "openapi_endpoint": ""},
    }

    app = get_app(override_config=config)
    actual_response = app.get("/openapi.json")

    assert actual_response.status_code == 404


def test_swagger_ui_available():
    config = {
        "swagger": {
            "enabled": "True",
            "swagger_ui_endpoint": "/ui",
            "openapi_endpoint": "/openapi.json",
        },
    }

    app = get_app(override_config=config)
    actual_response = app.get("/ui")

    assert actual_response.status_code == 200


def test_swagger_ui_not_available_with_empty_openapi_endpoint():
    config = {
        "swagger": {
            "enabled": "True",
            "swagger_ui_endpoint": "/ui",
            "openapi_endpoint": "",
        },
    }

    app = get_app(override_config=config)
    actual_response = app.get("/ui")

    print(actual_response.status_code)
    print(actual_response.text)

    assert actual_response.status_code == 404


def test_swagger_ui_not_available_with_empty_endpoint():
    config = {
        "swagger": {
            "enabled": "True",
            "swagger_ui_endpoint": "",
            "openapi_endpoint": "/openapi.json",
        },
    }

    app = get_app(override_config=config)
    actual_response = app.get("/ui")

    assert actual_response.status_code == 404


def test_redoc_available():
    config = {
        "swagger": {
            "enabled": "True",
            "redoc_endpoint": "/docs",
            "openapi_endpoint": "/openapi.json",
        },
    }

    app = get_app(override_config=config)
    actual_response = app.get("/docs")

    assert actual_response.status_code == 200


def test_redoc_not_available_with_empty_endpoint():
    config = {
        "swagger": {
            "enabled": "True",
            "redoc_endpoint": "",
            "openapi_endpoint": "/openapi.json",
        },
    }

    app = get_app(override_config=config)
    actual_response = app.get("/docs")

    assert actual_response.status_code == 404


def test_redoc_not_available_with_empty_openapi_endpoint():
    config = {
        "swagger": {
            "enabled": "True",
            "redoc_endpoint": "/docs",
            "openapi_endpoint": "",
        },
    }

    app = get_app(override_config=config)
    actual_response = app.get("/docs")

    assert actual_response.status_code == 404


def get_app(override_config: Optional[Dict[str, Dict[str, Optional[str]]]]):
    config = get_app_config(override_config)

    return TestClient(create_fastapi_app(config))


def get_app_test_config():
    return get_config("tests/max.test.conf")


def get_app_config(
    override_config: Optional[Dict[str, Dict[str, Optional[str]]]],
) -> ConfigParser:
    config = get_app_test_config()
    if override_config and len(override_config) > 0:
        for group, items in override_config.items():
            if not config.has_section(group):
                config.add_section(group)
            for key, value in items.items():
                config.remove_option(group, key)
                config.set(group, key, value)

    return config
