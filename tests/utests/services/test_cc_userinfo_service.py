from app.services.userinfo.cc_userinfo_service import CCUserinfoService

from unittest.mock import MagicMock


def test_request_userinfo_for_saml_artifact(
    tmp_path_factory, test_clients, test_client_id, test_client
):
    jwt_service_mock = MagicMock()
    authentication_context_mock = MagicMock()
    artifact_response_mock = MagicMock()

    authentication_context_mock.authorization_request = {"client_id": test_client_id}
    authentication_context_mock.session_id = "session_id"

    artifact_response_mock.get_bsn.return_value = "bsn"
    artifact_response_mock.loa_authn = "http://eidas.europa.eu/LoA/substantial"
    jwt_service_mock.create_jwe.return_value = "encrypted_jwt"

    service_to_test = CCUserinfoService(
        userinfo_jwt_service=jwt_service_mock,
        clients=test_clients,
    )

    expected_result = "encrypted_jwt"
    actual_result = service_to_test.request_userinfo_for_saml_artifact(
        authentication_context=authentication_context_mock,
        artifact_response=artifact_response_mock,
        subject_identifier="123456",
    )

    assert actual_result == expected_result

    jwt_service_mock.create_jwe.assert_called_once_with(
        encryption_certificate=test_client["certificate"],
        payload={
            "bsn": "bsn",
            "session_id": "session_id",
            "loa_authn": "http://eidas.europa.eu/LoA/substantial",
            "sub": "123456",
            "aud": test_client_id,
        },
    )
