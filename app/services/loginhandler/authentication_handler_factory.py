from app.exceptions.max_exceptions import UnauthorizedError
from app.services.loginhandler.authentication_handler import AuthenticationHandler
from app.services.loginhandler.irma_authentication_handler import IrmaAuthenticationHandler
from app.services.loginhandler.mock_saml_authentication_handler import MockSamlAuthenticationHandler
from app.services.loginhandler.saml_authentication_handler import SamlAuthenticationHandler


class AuthenticationHandlerFactory:

    def __init__(
            self,
            saml_authentication_handler: SamlAuthenticationHandler,
            mock_saml_authentication_handler: MockSamlAuthenticationHandler,
            irma_authentication_handler: IrmaAuthenticationHandler,
    ):
        self._saml_authentication_handler = saml_authentication_handler
        self._mock_saml_authentication_handler = mock_saml_authentication_handler
        self._irma_authentication_handler = irma_authentication_handler

    def create(self, authentication_method) -> AuthenticationHandler:
        if authentication_method == "digid":
            return self._saml_authentication_handler
        if authentication_method == "digid_mock":
            return self._mock_saml_authentication_handler
        if authentication_method == "irma":
            return self._irma_authentication_handler
        # todo correct exception here
        raise UnauthorizedError("unkown authentication_method")
