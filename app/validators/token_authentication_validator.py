import logging
import time
from typing import Dict, Any, Optional

from jwcrypto.common import JWException
from jwcrypto.jwt import JWT

from app.constants import CLIENT_ASSERTION_TYPE
from app.exceptions.max_exceptions import (
    InvalidRequestException,
    ServerErrorException,
    InvalidClientAssertionException,
)
from app.models.enums import ClientAssertionMethods

logger = logging.getLogger(__name__)


class TokenAuthenticationValidator:
    """
    a class to validate token endpoint authentication methods.
    current method supported is: private_key_jwt

    https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
    """

    def __init__(self, oidc_configuration_info: Dict[str, Any]):
        self.oidc_configuration_info = oidc_configuration_info
        self.assertion_methods = ClientAssertionMethods.to_list()

    def validate_client_authentication(
        self,
        client_id: str,
        client: Dict[str, Any],
        client_assertion_jwt: Optional[str],
        client_assertion_type: Optional[str],
    ) -> None:
        client_authentication_method = client.get("client_authentication_method")

        if (
            client_authentication_method is None
            or client_authentication_method not in self.assertion_methods
        ):
            raise ServerErrorException(
                error_description="Invalid client assertion method",
                log_message=f"{client_authentication_method} is not a valid method, make sure client_authentication_method is present in clients configuration with values {self.assertion_methods}",
            )

        if client_authentication_method == ClientAssertionMethods.NONE.value:
            logger.warning(
                " Client %s <id: %s> is using none as authentication method",
                client["name"],
                client_id,
            )
            return

        if client_assertion_jwt is None or client_assertion_type is None:
            raise InvalidRequestException(
                error_description="Invalid client authentication request"
            )

        if client_assertion_type != CLIENT_ASSERTION_TYPE:
            # see:
            # https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
            # https://rfc-editor.org/rfc/rfc7523.html#section-2.2
            # ToDo: move this validation to pydantic model once it parameters are required
            raise InvalidRequestException(
                error_description="Invalid client assertion type"
            )

        client_public_key = client["public_key"]
        try:
            client_assertion_jwt_claims = JWT(
                jwt=client_assertion_jwt,
                key=client_public_key,
                check_claims={
                    "iss": client_id,
                    "sub": client_id,
                    "aud": self.oidc_configuration_info.get("token_endpoint"),
                    "exp": int(time.time()),
                },
            )
            client_assertion_jwt_claims.validate(client_public_key)

        except (JWException, ValueError) as exception:
            logger.exception(exception)
            raise InvalidClientAssertionException() from exception
