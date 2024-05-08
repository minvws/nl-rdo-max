import pytest

from app.constants import CLIENT_ASSERTION_TYPE
from app.exceptions.max_exceptions import (
    InvalidClientAssertionException,
    ServerErrorException,
    InvalidRequestException,
)


def test_token_authentication_validator_success(
    token_authentication_validator, client_id, client, valid_client_jwt
):
    valid_client_jwt.make_signed_token(client["private_key"])
    client_assertion = valid_client_jwt.serialize()
    try:
        token_authentication_validator.validate_client_authentication(
            client_id=client_id,
            client=client,
            client_assertion_type=CLIENT_ASSERTION_TYPE,
            client_assertion_jwt=client_assertion,
        )

    except InvalidClientAssertionException:
        pytest.fail("InvalidClientAssertionException")


def test_authentication_with_invalid_jwt(
    token_authentication_validator, client_id, client, invalid_client_jwt
):
    invalid_client_jwt.make_signed_token(client["private_key"])
    client_assertion = invalid_client_jwt.serialize()

    with pytest.raises(InvalidClientAssertionException):
        token_authentication_validator.validate_client_authentication(
            client_id, client, client_assertion, CLIENT_ASSERTION_TYPE
        )


def test_authentication_with_invalid_client(
    token_authentication_validator, client_id, invalid_client, valid_client_jwt
):
    valid_client_jwt.make_signed_token(invalid_client["private_key"])
    client_assertion = valid_client_jwt.serialize()

    with pytest.raises(ServerErrorException):
        token_authentication_validator.validate_client_authentication(
            client_id, invalid_client, client_assertion, CLIENT_ASSERTION_TYPE
        )


def test_authentication_with_incorrect_query_param(
    token_authentication_validator, client_id, client, valid_client_jwt
):
    valid_client_jwt.make_signed_token(client["private_key"])
    client_assertion = valid_client_jwt.serialize()

    with pytest.raises(InvalidRequestException):
        token_authentication_validator.validate_client_authentication(
            client_id, client, client_assertion, "wrong_assertion_type"
        )
