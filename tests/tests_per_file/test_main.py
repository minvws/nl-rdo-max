import logging
import pytest
from inge6.main import validate_startup
from inge6.config import get_settings

def test_main():
    assert validate_startup()

@pytest.fixture
def mock_use_ssl():
    tmp = get_settings().use_ssl
    get_settings().use_ssl = 'true'
    yield
    get_settings().use_ssl = tmp

@pytest.fixture
def capture_logging(caplog):
    caplog.set_level(logging.DEBUG)

    yield caplog
    caplog.clear()

@pytest.fixture
def invalid_redis_settings():
    existing_redis_ssl = get_settings().redis.ssl
    get_settings().redis.ssl = True
    keys = [
        "host",
        "port",
        "enable_debugger",
        "key",
        "cert",
        "cafile",
        "object_ttl",
        "default_cache_namespace",
        "token_namespace",
        "refresh_token_namespace",
        "sub_id_namespace",
        "code_namespace"
    ]
    original_values = {}

    for key in keys:
        original_values[key] = getattr(get_settings().redis, key)
        setattr(get_settings().redis, key, "")

    yield

    get_settings().redis.ssl = existing_redis_ssl

    for item in original_values.items():
        setattr(get_settings().redis, item[0], item[1])

@pytest.mark.parametrize("section,setting",
    [
        ('saml', 'identity_provider_settings'),
        ('oidc', 'clients_file'),
        ('oidc', 'rsa_private_key'),
        ('oidc', 'rsa_public_key'),
        ('ssl', 'cert_file'),
        ('ssl', 'key_file'),
    ]
)
def test_missing_setting_files(section, setting, mocker, mock_use_ssl): # pylint: disable=unused-argument, redefined-outer-name
    mock_logger = mocker.patch('inge6.main.log')
    tmp = get_settings()[section][setting]
    get_settings()[section][setting] = 'idontexists.txt'
    assert not validate_startup()
    mock_logger.error.assert_called()
    get_settings()[section][setting] = tmp


@pytest.mark.parametrize("section,setting",
    [
        ('saml', 'identity_provider_settings'),
        ('oidc', 'clients_file'),
        ('oidc', 'rsa_private_key'),
        ('ssl', 'base_dir'),
    ]
)
def test_missing_setting_dirs(section, setting, mocker, mock_use_ssl): # pylint: disable=unused-argument, redefined-outer-name
    mock_logger = mocker.patch('inge6.main.log')
    tmp = get_settings()[section][setting]
    get_settings()[section][setting] = '/some/folder/doesnt/exist'
    assert not validate_startup()
    mock_logger.error.assert_called()
    get_settings()[section][setting] = tmp


def test_identity_providers_example(mock_valid_id_providers_settings_path):
    tmp = get_settings().saml.identity_provider_settings
    get_settings().saml.identity_provider_settings = mock_valid_id_providers_settings_path
    assert validate_startup()
    get_settings().saml.identity_provider_settings = tmp


@pytest.mark.idp_settings(base_dir='nonexistent/folder')
def test_identity_providers_example_errorneous_base_dir(mock_invalid_id_provider_setting_path, mocker):
    mock_logger = mocker.patch('inge6.main.log')
    tmp = get_settings().saml.identity_provider_settings
    get_settings().saml.identity_provider_settings = mock_invalid_id_provider_setting_path
    assert not validate_startup()
    mock_logger.error.assert_called()
    get_settings().saml.identity_provider_settings = tmp


@pytest.mark.idp_settings(
    [
        {'base_dir': 'nonexistent/folder'},
        {'cert_path': 'nonexistent/file.txt'},
        {'key_path': 'nonexistent/file.txt'},
        {'settings_path': 'nonexistent/file.txt'},
        {'idp_metadata_path': 'nonexistent/file.txt'}
    ]
)
def test_identity_providers_example_errorneous(mock_invalid_id_provider_setting_path, mocker):
    mock_logger = mocker.patch('inge6.main.log')

    for mock_idp_setting_path in mock_invalid_id_provider_setting_path:
        tmp = get_settings().saml.identity_provider_settings
        get_settings().saml.identity_provider_settings = mock_idp_setting_path
        assert not validate_startup()
        mock_logger.error.assert_called()
        get_settings().saml.identity_provider_settings = tmp


def test_redis_settings_errorneous(capture_logging, invalid_redis_settings): # pylint: disable=unused-argument, redefined-outer-name
    assert not validate_startup()
    keys = [
        "host",
        "port",
        "enable_debugger",
        "key",
        "cert",
        "cafile",
        "object_ttl",
        "default_cache_namespace",
        "token_namespace",
        "refresh_token_namespace",
        "sub_id_namespace",
        "code_namespace"
    ]
    for key in keys:
        assert 'redis.{}'.format(key) in capture_logging.text

    capture_logging.clear()
