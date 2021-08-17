import pytest

from inge6.config import settings

@pytest.fixture
def digid_config():
    tmp_idp = settings.connect_to_idp
    tmp_saml_certpath = settings.saml.cert_path
    tmp_saml_keypath = settings.saml.key_path
    tmp_saml_settingspath = settings.saml.settings_path
    settings.connect_to_idp = 'digid'
    settings.saml.cert_path = 'saml/digid/certs/sp.crt'
    settings.saml.key_path = 'saml/digid/certs/sp.key'
    settings.saml.settings_path = 'saml/digid/settings.json'
    yield
    settings.connect_to_idp = tmp_idp
    settings.saml.cert_path = tmp_saml_certpath
    settings.saml.key_path = tmp_saml_keypath
    settings.saml.settings_path = tmp_saml_settingspath

@pytest.fixture
def tvs_config():
    tmp_idp = settings.connect_to_idp
    tmp_saml_certpath = settings.saml.cert_path
    tmp_saml_keypath = settings.saml.key_path
    tmp_saml_settingspath = settings.saml.settings_path
    settings.connect_to_idp = 'tvs'
    settings.saml.cert_path = 'saml/tvs/certs/sp.crt'
    settings.saml.key_path = 'saml/tvs/certs/sp.key'
    settings.saml.settings_path = 'saml/tvs/settings.json'
    yield
    settings.connect_to_idp = tmp_idp
    settings.saml.cert_path = tmp_saml_certpath
    settings.saml.key_path = tmp_saml_keypath
    settings.saml.settings_path = tmp_saml_settingspath

@pytest.fixture
def disable_digid_mock():
    tmp = settings.mock_digid
    settings.mock_digid = 'false'
    yield
    settings.mock_digid = tmp
