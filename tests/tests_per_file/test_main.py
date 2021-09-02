import pytest

from inge6.main import validate_startup
from inge6.config import settings

def test_main():
    assert validate_startup()

@pytest.fixture
def mock_use_ssl():
    tmp = settings.use_ssl
    settings.use_ssl = 'true'
    yield
    settings.use_ssl = tmp

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
    tmp = settings[section][setting]
    settings[section][setting] = 'idontexists.txt'
    assert not validate_startup()
    mock_logger.error.assert_called()
    settings[section][setting] = tmp


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
    tmp = settings[section][setting]
    settings[section][setting] = '/some/folder/doesnt/exist'
    assert not validate_startup()
    mock_logger.error.assert_called()
    settings[section][setting] = tmp


def test_identity_providers_example(mock_valid_id_providers_settings_path):
    tmp = settings.saml.identity_provider_settings
    settings.saml.identity_provider_settings = mock_valid_id_providers_settings_path
    assert validate_startup()
    settings.saml.identity_provider_settings = tmp


@pytest.mark.idp_settings(base_dir='nonexistent/folder')
def test_identity_providers_example_errorneous_base_dir(mock_invalid_id_provider_setting_path, mocker):
    mock_logger = mocker.patch('inge6.main.log')
    tmp = settings.saml.identity_provider_settings
    settings.saml.identity_provider_settings = mock_invalid_id_provider_setting_path
    assert not validate_startup()
    mock_logger.error.assert_called()
    settings.saml.identity_provider_settings = tmp


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
        tmp = settings.saml.identity_provider_settings
        settings.saml.identity_provider_settings = mock_idp_setting_path
        assert not validate_startup()
        mock_logger.error.assert_called()
        settings.saml.identity_provider_settings = tmp
