import abc
from typing import Any, Dict

from fastapi import Request
from pyop.message import AuthorizationRequest
from starlette.responses import Response

from app.models.authorize_request import AuthorizeRequest


class AuthenticationHandler(abc.ABC):
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
    ) -> Response:
        pass
