from inge6.models import AuthorizeRequest


def test_authorization_request(caplog, default_authorize_request_dict):
    AuthorizeRequest(**default_authorize_request_dict)
    assert "Scope" not in caplog.text
    assert "not allowed, only" not in caplog.text
    assert "are supported" not in caplog.text

    unsupported_scope_request = default_authorize_request_dict
    unsupported_scope_request["scope"] = "email profile openid"

    AuthorizeRequest(**default_authorize_request_dict)
    assert (
        f"Scope email not allowed, only {AuthorizeRequest.get_allowed_scopes()} are supported"
        in caplog.text
    )
    assert (
        f"Scope profile not allowed, only {AuthorizeRequest.get_allowed_scopes()} are supported"
        in caplog.text
    )
