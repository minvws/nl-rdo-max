import pytest
from inge6 import cache
from inge6.config import get_settings
from inge6.provider import Provider

@pytest.fixture
def mock_clients_db(mocker, mock_provider): # pylint: disable=redefined-outer-name
    mocker.patch.object(mock_provider.provider, 'clients', {
        "test_client": {
            "token_endpoint_auth_method": "none",
            "redirect_uris": [
                    "http://localhost:3000/login",
                ],
            "response_types": ["code"]
        }
    })
    yield mock_provider

@pytest.fixture
def redis_mock(redisdb, mocker):
    mocker.patch('inge6.cache.redis_cache.create_redis_client', lambda _: redisdb)
    yield redisdb

@pytest.fixture
def mock_provider(redis_mock): # pylint: disable=unused-argument, redefined-outer-name
    return Provider()

@pytest.fixture()
def redis_cache(redis_mock): # pylint: disable=redefined-outer-name, unused-argument
    # pylint: disable=W0212
    # Access to a protected member
    yield cache.redis_cache.RedisCache(settings=get_settings(), redis_client=redis_mock)

# pylint: disable=redefined-outer-name, unused-argument
@pytest.fixture
def digid_config(redis_mock):
    redis_mock.set(get_settings().primary_idp_key, 'digid')

# pylint: disable=redefined-outer-name, unused-argument
@pytest.fixture
def tvs_config(redis_mock):
    redis_mock.set(get_settings().primary_idp_key, 'tvs')

@pytest.fixture
def digid_mock_disable():
    tmp = get_settings().mock_digid
    get_settings().mock_digid = 'false'
    yield
    get_settings().mock_digid = tmp


@pytest.fixture
def digid_mock_enable():
    tmp = get_settings().mock_digid
    get_settings().mock_digid = 'true'
    yield
    get_settings().mock_digid = tmp

def get_mock_tvs_idp_settings_data(
    saml_spec_version = 4.5,
    base_dir = "saml/tvs",
    cert_path = "saml/tvs/certs/sp.crt",
    key_path = "saml/tvs/certs/sp.key",
    settings_path = "saml/tvs/settings.json",
    idp_metadata_path = "saml/tvs/metadata/idp_metadata.xml",
): return"""{{"tvs": {{
        "saml_specification_version": "{saml_spec_version}",
        "base_dir": "{base_dir}",
        "cert_path": "{cert_path}",
        "key_path": "{key_path}",
        "settings_path": "{settings_path}",
        "idp_metadata_path": "{idp_metadata_path}" 
    }}
}}
""".replace('\n', '').format(saml_spec_version=saml_spec_version, base_dir=base_dir, cert_path=cert_path,
            key_path=key_path, settings_path=settings_path, idp_metadata_path=idp_metadata_path)

@pytest.fixture
def mock_valid_id_providers_settings_path(tmp_path):
    identity_providers_file_path = tmp_path / "identity_providers_test.json"
    identity_providers_file_path.write_text(get_mock_tvs_idp_settings_data())
    yield str(identity_providers_file_path)

@pytest.fixture
def mock_invalid_id_provider_setting_path(request, tmp_path):
    idp_settings_mark = request.node.get_closest_marker("idp_settings")

    if len(idp_settings_mark.args) == 0:
        identity_providers_file_path = tmp_path / "identity_providers_test.json"
        identity_providers_file_path.write_text(get_mock_tvs_idp_settings_data(**idp_settings_mark.kwargs))
        yield str(identity_providers_file_path)
    else:
        paths = []
        for index, fake_settings in enumerate(idp_settings_mark.args[0]):
            identity_providers_file_path = tmp_path / f"identity_providers_test({index}).json"
            identity_providers_file_path.write_text(get_mock_tvs_idp_settings_data(**fake_settings))
            paths.append(str(identity_providers_file_path))
        yield paths
