import abc
from typing import Any, Dict

from fastapi import Request
from pyop.message import AuthorizationRequest

from app.models.authorize_request import AuthorizeRequest
from app.models.authorize_response import AuthorizeResponse


class ExchangeBasedAuthenticationHandler(abc.ABC):
    @abc.abstractmethod
    def authentication_state(
        self, authorize_request: AuthorizeRequest
    ) -> Dict[str, Any]:
        pass

    @abc.abstractmethod
    def authorize_response(
        self,
        request: Request,
        authorize_request: AuthorizeRequest,
        pyop_authentication_request: AuthorizationRequest,
        authentication_state: Dict[str, Any],
        randstate: str,
    ) -> AuthorizeResponse:
        pass

    @abc.abstractmethod
    def get_external_session_status(self, exchange_token: str) -> str:
        pass
