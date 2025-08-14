from unittest.mock import MagicMock, patch
import pytest

from app.models.authentication_meta import AuthenticationMeta
from app.services.encryption.jwt_service import JWTService
from app.services.userinfo.cibg_userinfo_service import CIBGUserinfoService
from tests.utils import make_test_certificate


@pytest.fixture
def mock_jwt_service():
    return MagicMock(spec=JWTService)


@pytest.fixture
def cibg_service(mock_jwt_service):
    return CIBGUserinfoService(
        userinfo_jwt_service=mock_jwt_service,
        cibg_jwt_service=mock_jwt_service,
        environment="test",
        clients={},
        ssl_client_key_path=None,
        ssl_client_crt_path=None,
        ssl_client_verify=False,
        cibg_exchange_token_endpoint="https://example.com/token",
        cibg_saml_endpoint="https://example.com/saml",
        cibg_userinfo_audience="audience",
        req_issuer="req_issuer",
        external_http_requests_timeout_seconds=5,
        external_base_url="https://example.com/",
    )


def test_request_userinfo_jwe(cibg_service):
    # Prepare test data
    certificate, private_key = make_test_certificate()
    client = {"certificate": certificate, "external_id": "test-external-id"}
    client_id = "test-client-id"
    auth_type = "digid"
    json_schema = "https://example.com/json_schema.json"
    sub = "subject-identifier"
    authentication_meta = AuthenticationMeta(
        ip="000.000.000.000",
        headers={"User-Agent": "test-agent"},
        authentication_method_name="test-auth-method",
    )

    # Patch jwt_service.create_jwt to return a dummy JWT
    cibg_service.userinfo_jwt_service.create_jwt = MagicMock(
        return_value="dummy-jwt-token"
    )

    # Patch requests.request to return a mock response with a fake JWE in the Authorization header
    class MockResponse:
        status_code = 200
        headers = {"Authorization": "Bearer fake-jwe-token"}

    with patch(
        "app.services.userinfo.cibg_userinfo_service.request",
        return_value=MockResponse(),
    ):
        jwe_token = cibg_service._request_userinfo(
            cibg_endpoint="https://example.com/userinfo",
            client_id=client_id,
            client=client,
            auth_type=auth_type,
            json_schema=json_schema,
            sub=sub,
            authentication_meta=authentication_meta,
        )
        assert jwe_token == "fake-jwe-token"


def test_create_jwt_payload_fields(cibg_service):
    from app.models.authentication_meta import AuthenticationMeta

    certificate, private_key = make_test_certificate()
    authentication_meta = AuthenticationMeta(
        ip="000.000.000.000",
        headers={"User-Agent": "test-agent"},
        authentication_method_name="test-auth-method",
    )
    payload = cibg_service._create_jwt_payload(
        client_certificate=certificate,
        external_id="external-id",
        client_id="client-id",
        auth_type="digid",
        json_schema="https://example.com/schema.json",
        sub="subject-identifier",
        authentication_meta=authentication_meta,
        saml_id="saml-id",
        loa_authn="loa-authn",
        exchange_token="exchange-token",
        req_acme_tokens=["token1", "token2"],
    )

    # Assert required fields
    assert payload["aud"] == cibg_service._cibg_userinfo_audience
    assert payload["ura"] == "external-id"
    assert payload["x5c"] == certificate.pem
    assert payload["auth_type"] == "digid"
    assert payload["meta"] == authentication_meta.model_dump()
    assert payload["loa_authn"] == "loa-authn"
    assert payload["saml_id"] == "saml-id"
    assert payload["exchange_token"] == "exchange-token"
    assert payload["req_claims"]["iss"] == cibg_service._req_issuer
    assert payload["req_claims"]["aud"] == "client-id"
    assert payload["req_claims"]["sub"] == "subject-identifier"
    assert payload["req_claims"]["json_schema"] == "https://example.com/schema.json"
    assert payload["req_claims"]["req_acme_tokens"] == ["token1", "token2"]
