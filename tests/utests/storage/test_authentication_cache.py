import base64
import json
from unittest.mock import MagicMock

from app.models.acs_context import AcsContext
from app.models.authentication_context import AuthenticationContext
from app.models.authentication_request_context import UserinfoContext
from app.services.encryption.sym_encryption_service import SymEncryptionService
from app.storage.authentication_cache import AuthenticationCache
from app.storage.cache import Cache
from pyop.message import AuthorizationRequest


def create_authentication_cache(
    cache: Cache = MagicMock(),
    sym_encryption_service: SymEncryptionService = MagicMock(),
    app_mode: str = None,
):
    return AuthenticationCache(cache, sym_encryption_service, app_mode)


def test_create_randstate():
    pyop_authentication_request = MagicMock(spec=AuthorizationRequest)
    authorize_request = MagicMock()
    cache = MagicMock()

    pyop_authentication_request.__getitem__.side_effect = {
        "redirect_uri": "redirect_uri"
    }

    authorize_request.login_hints = ["login_hint"]
    authorize_request.authorization_by_proxy = False
    authorize_request.client_id = "client_id"
    expected = base64.b64encode(
        json.dumps(
            {"state": "bla", "client_id": "client_id", "redirect_uri": "redirect_uri"}
        ).encode("utf-8")
    ).decode("utf-8")

    cache.gen_token.return_value = "bla"

    acache = create_authentication_cache(cache)

    actual = acache.create_randstate(
        pyop_authentication_request,
        authorize_request,
    )

    assert actual == expected


def test_create_authentication_request_state():
    pyop_authentication_request = MagicMock(spec=AuthorizationRequest)
    authorize_request = MagicMock()
    authentication_state = MagicMock()
    cache = MagicMock()

    pyop_authentication_request.__getitem__.side_effect = {
        "redirect_uri": "redirect_uri"
    }

    authorize_request.login_hints = ["login_hint"]
    authorize_request.authorization_by_proxy = False
    authorize_request.client_id = "client_id"

    cache.gen_token.return_value = "bla"

    acache = create_authentication_cache(cache)

    acache.cache_authentication_request_state(
        pyop_authentication_request,
        authorize_request,
        "randstate",
        authentication_state,
        "login_option",
        "session_id",
        req_acme_tokens=None,
        sub="123456",
    )

    cache.set_complex_object.assert_called_with(
        "auth_req:randstate",
        AuthenticationContext(
            authorization_request=pyop_authentication_request,
            authorization_by_proxy=authorize_request.authorization_by_proxy,
            authentication_method="login_option",
            authentication_state=authentication_state,
            session_id="session_id",
            sub="123456",
        ),
    )


def test_get_authentication_request_state():
    cache = MagicMock()

    randstate = "bla"
    expected = MagicMock()

    cache.get_and_delete_complex_object.return_value = expected

    acache = create_authentication_cache(cache)
    actual = acache.get_authentication_request_state(randstate)

    assert actual == expected
    cache.get_and_delete_complex_object.assert_called_with(
        "auth_req:" + randstate, AuthenticationContext
    )


def test_cache_acs_context():
    cache = MagicMock()
    code = MagicMock(name="code")
    acs_context = MagicMock()

    acache = create_authentication_cache(cache)
    acache.cache_acs_context(code, acs_context)

    cache.set_complex_object.assert_called_with(
        f"pyop_auth_req:{code}",
        acs_context,
    )


def test_get_acs_context():
    cache = MagicMock()

    code = "code"
    expected = MagicMock()

    cache.get_and_delete_complex_object.return_value = expected

    acache = create_authentication_cache(cache)
    actual = acache.get_acs_context(code)

    assert actual == expected
    cache.get_and_delete_complex_object.assert_called_with(
        "pyop_auth_req:" + code, AcsContext
    )


def test_cache_userinfo_context():
    cache = MagicMock()
    sym_encryption_service = MagicMock()
    acs_context = MagicMock()
    acs_context.client_id = "client_id"
    acs_context.authentication_method = "authentication_method"
    acs_context.userinfo = "userinfo"
    acs_context.sub = "123456"
    sym_encryption_service.symm_encrypt.return_value = "encrypted"
    userinfo_key = "userinfo_key"
    access_token = "access_token"

    acache = create_authentication_cache(cache, sym_encryption_service)
    acache.cache_userinfo_context(userinfo_key, access_token, acs_context)

    cache.set.assert_called_with("access_token:" + "userinfo_key", "encrypted")
    expected = json.dumps(
        {
            "client_id": "client_id",
            "authentication_method": "authentication_method",
            "access_token": "access_token",
            "sub": "123456",
            "userinfo": "userinfo",
        }
    )
    sym_encryption_service.symm_encrypt.assert_called_with(expected.encode("utf-8"))


def test_get_userinfo_context():
    cache = MagicMock()
    sym_encryption_service = MagicMock()

    access_token = "access_token"
    encrypted = MagicMock(name="encrypted")
    userinfo_context = UserinfoContext(
        **{
            "client_id": "client_id",
            "authentication_method": "authentication_method",
            "access_token": "access_token",
            "userinfo": "userinfo",
            "sub": "123456",
        }
    )

    cache.get.return_value = encrypted
    sym_encryption_service.symm_decrypt.return_value = userinfo_context.json().encode(
        "utf-8"
    )

    acache = create_authentication_cache(cache, sym_encryption_service)
    actual = acache.get_userinfo_context(access_token)

    assert actual == userinfo_context
    cache.get.assert_called_with("access_token:" + access_token)
    sym_encryption_service.symm_decrypt.assert_called_with(encrypted)
