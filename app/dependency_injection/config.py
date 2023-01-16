import configparser
from typing import Any

_PATH = "max.conf"
_CONFIG = None


# pylint:disable=global-statement
def get_config(path=None) -> configparser.ConfigParser:
    """
    Use this method only when it's not possible to inject config variables
    """
    global _CONFIG
    global _PATH
    if path is None:
        path = _PATH
    if _CONFIG is None or _PATH != path:
        _PATH = path
        _CONFIG = configparser.ConfigParser()
        _CONFIG.read(_PATH)
    return _CONFIG


def get_config_value(section: str, name: str, default: Any = None) -> Any:
    """
    Use this method only when it's not possible to inject config variables
    """
    config = get_config()
    if section in config and name in config[section]:
        return get_config()[section][name]
    return default


# pylint:disable=too-few-public-methods
class RouterConfig:
    authorize_endpoint = get_config_value(
        "oidc", "authorize_endpoint", "/authorize_endpoint"
    )
    accesstoken_endpoint = get_config_value(
        "oidc", "accesstoken_endpoint", "/accesstoken_endpoint"
    )
    jwks_endpoint = get_config_value("oidc", "jwks_endpoint", "/jwks_endpoint")
    health_endpoint = get_config_value("misc", "health_endpoint", "/health_endpoint")
    userinfo_endpoint = get_config_value(
        "oidc", "userinfo_endpoint", "/userinfo_endpoint"
    )