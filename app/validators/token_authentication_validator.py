import logging
import time
from typing import Dict, Any, Optional

from app.constants import CLIENT_ASSERTION_TYPE
from app.exceptions.max_exceptions import (
    InvalidRequestException,
    ServerErrorException,
    InvalidClientAssertionException,
)
from app.models.enums import ClientAssertionMethods
from app.services.encryption.jwt_service import from_jwt

logger = logging.getLogger(__name__)


class TokenAuthenticationValidator:
    """
    Validates client authentication for the OAuth2/OIDC token endpoint, specifically supporting the
    `private_key_jwt` method as described in the OpenID Connect Core specification
    (see: https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication).

    This validator is necessary because the pyOP library does not natively support `private_key_jwt`
    authentication. Instead, this class implements the required logic to verify client assertions using
    JWTs signed with the client's private key.

    Usage:
        - In the clients.json file, set the client's `token_endpoint_auth_method` to `none` (for pyOP compatibility).
        - In the same clients.json file, set the custom field `client_authentication_method` to `private_key_jwt`
          to enable this validation.
        - The validator checks the presence and validity of the client assertion JWT, its type, and verifies
          the JWT claims and signature using the client's public key.

    For more details on the `private_key_jwt` authentication method, refer to the OpenID Connect Core specification:
    https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication

    Raises:
        - ServerErrorException: If the client authentication method is invalid or misconfigured.
        - InvalidRequestException: If required authentication parameters are missing or incorrect.
        - InvalidClientAssertionException: If the client assertion JWT is invalid or cannot be verified.
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

        client_certificate = client["certificate"]
        claims = from_jwt(
            jwt_pub_key=client_certificate.jwk,
            jwt_str=client_assertion_jwt,
            check_claims={
                "iss": client_id,
                "sub": client_id,
                "aud": self.oidc_configuration_info.get("token_endpoint"),
                "exp": int(time.time()),
            },
        )
        if claims is None:
            raise InvalidClientAssertionException()
