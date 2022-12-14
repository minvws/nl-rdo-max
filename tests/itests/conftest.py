import pytest
from pytest_redis import factories

from inge6 import cache
from inge6.provider import Provider

from ..test_utils import get_settings

redis_config = factories.redis_noproc(port=16379)
redis = factories.redisdb("redis_config")


@pytest.fixture
# pylint: disable=redefined-outer-name
# pylint: disable=unused-argument
def redis_mock(docker_services, redis, mocker):
    redis.set(get_settings().primary_idp_key, "tvs")
    mocker.patch("inge6.cache.redis_cache.create_redis_client", lambda _: redis)
    mocker.patch(
        "inge6.cache.redis_cache.RedisCache.client_factory", lambda *a, **k: redis
    )
    yield redis


@pytest.fixture
def default_settings():
    yield get_settings()


@pytest.fixture
def mock_provider(
    redis_mock, default_settings
):  # pylint: disable=unused-argument, redefined-outer-name
    return Provider(settings=default_settings)


@pytest.fixture()
def redis_cache(redis_mock):  # pylint: disable=redefined-outer-name, unused-argument
    # pylint: disable=W0212
    # Access to a protected member
    yield cache.redis_cache.RedisCache(settings=get_settings(), redis_client=redis_mock)


# pylint: disable=redefined-outer-name, unused-argument
@pytest.fixture
def digid_config(redis_mock):
    redis_mock.set(get_settings().primary_idp_key, "digid")


# pylint: disable=redefined-outer-name, unused-argument
@pytest.fixture
def tvs_config(redis_mock):
    redis_mock.set(get_settings().primary_idp_key, "tvs")


def get_mock_tvs_idp_settings_data(
    saml_spec_version=4.5,
    base_dir="saml/tvs",
    cert_path="saml/tvs/certs/sp.crt",
    key_path="saml/tvs/certs/sp.key",
    advanced_settings_path="saml/tvs/advanced_settings.json",
    settings_path="saml/tvs/settings.json",
    idp_metadata_path="saml/tvs/metadata/idp_metadata.xml",
):
    return """{{"tvs": {{
        "saml_specification_version": "{saml_spec_version}",
        "base_dir": "{base_dir}",
        "cert_path": "{cert_path}",
        "key_path": "{key_path}",
        "settings_path": "{settings_path}",
        "advanced_settings_path": "{advanced_settings_path}",
        "idp_metadata_path": "{idp_metadata_path}" 
    }}
}}
""".replace(
        "\n", ""
    ).format(
        saml_spec_version=saml_spec_version,
        base_dir=base_dir,
        cert_path=cert_path,
        key_path=key_path,
        advanced_settings_path=advanced_settings_path,
        settings_path=settings_path,
        idp_metadata_path=idp_metadata_path,
    )


@pytest.fixture
def mock_valid_id_providers_settings_path(tmp_path):
    identity_providers_file_path = tmp_path / "identity_providers_test.json"
    identity_providers_file_path.write_text(get_mock_tvs_idp_settings_data())
    yield str(identity_providers_file_path)


@pytest.fixture
def mockpath_tvs_machtigen_provider_settings(tmp_path):
    identity_providers_file_path = tmp_path / "identity_providers_test.json"
    identity_providers_file_path.write_text(
        get_mock_tvs_idp_settings_data(
            base_dir="tests/resources/saml_provider_settings/tvs_machtigen",
            settings_path="tests/resources/saml_provider_settings/tvs_machtigen/settings.json",
            advanced_settings_path="tests/resources/saml_provider_settings/tvs_machtigen/advanced_settings.json",
            idp_metadata_path="tests/resources/saml_provider_settings/tvs_machtigen/metadata/idp_metadata.xml",
        )
    )
    yield str(identity_providers_file_path)


@pytest.fixture
def mock_invalid_id_provider_setting_path(request, tmp_path):
    idp_settings_mark = request.node.get_closest_marker("idp_settings")

    if len(idp_settings_mark.args) == 0:
        identity_providers_file_path = tmp_path / "identity_providers_test.json"
        identity_providers_file_path.write_text(
            get_mock_tvs_idp_settings_data(**idp_settings_mark.kwargs)
        )
        yield str(identity_providers_file_path)
    else:
        paths = []
        for index, fake_settings in enumerate(idp_settings_mark.args[0]):
            identity_providers_file_path = (
                tmp_path / f"identity_providers_test({index}).json"
            )
            identity_providers_file_path.write_text(
                get_mock_tvs_idp_settings_data(**fake_settings)
            )
            paths.append(str(identity_providers_file_path))
        yield paths


@pytest.fixture
def default_authorize_request_dict():
    return {
        "client_id": "test_client",
        "redirect_uri": "http://localhost:3000/login",
        "response_type": "code",
        "nonce": "n-0S6_WzA2Mj",
        "state": "af0ifjsldkj",
        "scope": "openid",
        "code_challenge": "_1f8tFjAtu6D1Df-GOyDPoMjCJdEvaSWsnqR6SLpzsw",  # code_verifier : SoOEDN-mZKNhw7Mc52VXxyiqTvFB3mod36MwPru253c
        "code_challenge_method": "S256",
    }


@pytest.fixture
def mock_clients_db():
    return {
        "test_client": {
            "token_endpoint_auth_method": "none",
            "redirect_uris": [
                "http://localhost:3000/login",
            ],
            "response_types": ["code"],
        }
    }
