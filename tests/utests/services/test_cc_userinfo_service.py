from app.services.userinfo.cc_userinfo_service import CCUserinfoService

from unittest.mock import MagicMock


def test_request_userinfo_for_digid_artifact(tmp_path_factory, mocker):
    example_cert = """
-----BEGIN CERTIFICATE-----
MIICUTCCAfugAwIBAgIBADANBgkqhkiG9w0BAQQFADBXMQswCQYDVQQGEwJDTjEL
-----END CERTIFICATE-----"""

    tmp_path = tmp_path_factory.mktemp("client_pubkey_path")
    mocker.patch(
        "app.services.userinfo.cc_userinfo_service.file_content_raise_if_none",
        return_value=example_cert,
    )

    jwe_service_provider_mock = MagicMock()
    jwe_service_mock = MagicMock()
    authentication_context_mock = MagicMock()
    artifact_response_mock = MagicMock()
    saml_identity_provider_mock = MagicMock()

    authentication_context_mock.authorization_request = {"client_id": "client_id"}

    clients = {
        "client_id": {
            "client_public_key_path": tmp_path / "client_pubkey",
            "pubkey_type": "pubkey_type",
        }
    }

    artifact_response_mock.get_bsn.return_value = "bsn"
    jwe_service_provider_mock.get_jwe_service.return_value = jwe_service_mock
    jwe_service_mock.to_jwe.return_value = "encrypted_jwt"

    service_to_test = CCUserinfoService(
        jwe_service_provider=jwe_service_provider_mock,
        clients=clients,
        app_mode="None",
        req_issuer="req_issuer",
        jwt_expiration_duration=60,
        jwt_nbf_lag=10,
    )

    expected_result = "encrypted_jwt"
    actual_result = service_to_test.request_userinfo_for_digid_artifact(
        authentication_context=authentication_context_mock,
        artifact_response=artifact_response_mock,
        saml_identity_provider=saml_identity_provider_mock,
    )

    assert actual_result == expected_result

    jwe_service_mock.to_jwe.assert_called_once_with(
        {
            "bsn": "bsn",
            "iss": "req_issuer",
            "aud": "client_id",
            "nbf": mocker.ANY,
            "exp": mocker.ANY,
            "x5c": "MIICUTCCAfugAwIBAgIBADANBgkqhkiG9w0BAQQFADBXMQswCQYDVQQGEwJDTjEL",
        },
        example_cert,
    )
