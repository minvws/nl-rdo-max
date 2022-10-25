import pytest

from unittest.mock import MagicMock, patch, call

from app.services.encryption.sym_encryption_service import SymEncryptionService
from app.storage.authentication_cache import AuthenticationCache
from app.storage.cache import Cache


def create_authentication_cache(
    cache: Cache = MagicMock(),
    sym_encryption_service: SymEncryptionService = MagicMock(),
    app_mode: str = None
):
    return AuthenticationCache(
        cache,
        sym_encryption_service,
        app_mode
    )


def test_create_authentication_request_state():
    pyop_authentication_request = MagicMock()
    authorize_request = MagicMock()
    identity_provider_name = "ipn"
    cache = MagicMock()

    expected = "bla"

    cache.gen_token.return_value = expected

    ac = create_authentication_cache(cache)

    actual = ac.create_authentication_request_state(
        pyop_authentication_request,
        authorize_request,
        identity_provider_name
    )

    cache.set_complex_object.assert_called_with(
        "auth_req:" + expected,
        {
            "auth_req": pyop_authentication_request,
            "code_challenge": authorize_request.code_challenge,
            "code_challenge_method": authorize_request.code_challenge_method,
            "authorization_by_proxy": authorize_request.authorization_by_proxy,
            "id_provider": identity_provider_name,
            "client_id": authorize_request.client_id
        }
    )
    assert actual == expected


def test_get_authentication_request_state():
    cache = MagicMock()

    randstate = "bla"
    expected = MagicMock()

    cache.get_complex_object.return_value = expected

    ac = create_authentication_cache(cache)
    actual = ac.get_authentication_request_state(randstate)

    assert actual == expected
    cache.get_complex_object.assert_called_with("auth_req:" + randstate)


def test_cache_acs_context():
    cache = MagicMock()
    pyop_authorize_response = MagicMock()
    pyop_authorize_request = MagicMock()
    acs_request = MagicMock()

    ac = create_authentication_cache(cache)
    ac.cache_acs_context(
        pyop_authorize_response,
        pyop_authorize_request,
        acs_request)

    cache.set_complex_object.assert_called_with(
        "pyop_auth_req:" + str(pyop_authorize_response['code']),
        {
            "id_provider": pyop_authorize_request["id_provider"],
            "authorization_by_proxy": pyop_authorize_request["authorization_by_proxy"],
            "code_challenge": pyop_authorize_request["code_challenge"],
            "code_challenge_method": pyop_authorize_request["code_challenge_method"],
            "artifact": acs_request.SAMLart,
            "mocking": acs_request.mocking,
            "client_id": pyop_authorize_request["client_id"]
        })


def test_get_acs_context():
    cache = MagicMock()

    code = "code"
    expected = MagicMock()

    cache.get_complex_object.return_value = expected

    ac = create_authentication_cache(cache)
    actual = ac.get_acs_context(code)

    assert actual == expected
    cache.get_complex_object.assert_called_with("pyop_auth_req:" + code)


def test_cache_authentication_context():
    cache = MagicMock()
    sym_encryption_service = MagicMock()
    pyop_token_response = MagicMock()
    external_user_authentication_context = MagicMock()
    sym_encryption_service.symm_encrypt.return_value = "encrypted"
    external_user_authentication_context.encode.return_value = "encoded"

    ac = create_authentication_cache(cache, sym_encryption_service)
    ac.cache_authentication_context(
        pyop_token_response,
        external_user_authentication_context)

    cache.set_complex_object.assert_called_with(
        "access_token:" + str(pyop_token_response['access_token']),
        {
            "id_token": pyop_token_response["id_token"],
            "external_user_authentication_context": "encrypted"
        })
    sym_encryption_service.symm_encrypt.assert_called_with("encoded")
    external_user_authentication_context.encode.assert_called_with("utf-8")


def test_get_authentication_context():
    cache = MagicMock()
    sym_encryption_service = MagicMock()

    access_token = "access_token"
    decrypted = MagicMock(name="decrypted")
    decoded = MagicMock(name="decoded")
    from_cache = {"external_user_authentication_context": "euac"}

    cache.get_complex_object.return_value = from_cache
    sym_encryption_service.symm_decrypt.return_value = decrypted
    decrypted.decode.return_value = decoded

    ac = create_authentication_cache(cache, sym_encryption_service)
    actual = ac.get_authentication_context(access_token)

    assert actual == from_cache
    assert from_cache["external_user_authentication_context"] == decoded
    cache.get_complex_object.assert_called_with("access_token:" + access_token)
    sym_encryption_service.symm_decrypt.assert_called_with("euac")
    decrypted.decode.assert_called_with("utf-8")
