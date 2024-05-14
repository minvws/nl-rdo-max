# pylint:disable=unused-argument
def test_openid_configuration(lazy_app, config, app_mode_default, client):
    app = lazy_app.value
    issuer_url = config["oidc"]["issuer"]
    openid_configuration = app.get(".well-known/openid-configuration").json()
    assert openid_configuration == {
        "version": "3.0",
        "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
        "claims_parameter_supported": True,
        "request_parameter_supported": False,
        "request_uri_parameter_supported": True,
        "require_request_uri_registration": False,
        "grant_types_supported": ["authorization_code"],
        "frontchannel_logout_supported": False,
        "frontchannel_logout_session_supported": False,
        "backchannel_logout_supported": False,
        "backchannel_logout_session_supported": False,
        "issuer": issuer_url,
        "authorization_endpoint": issuer_url + "/authorize",
        "jwks_uri": issuer_url + "/jwks",
        "token_endpoint": issuer_url + "/token",
        "scopes_supported": ["openid"],
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "subject_types_supported": ["pairwise"],
        "userinfo_endpoint": issuer_url + "/userinfo",
        "id_token_signing_alg_values_supported": ["RS256"],
        "code_challenge_methods_supported": ["S256"],
    }
