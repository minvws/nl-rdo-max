import logging
from pydantic import BaseModel, validator
from functools import cached_property

from app.models.response_type import ResponseType
from app import constants


log = logging.getLogger(__package__)


class AuthorizeRequest(BaseModel, keep_untouched=(cached_property,)):
    client_id: str
    redirect_uri: str
    response_type: ResponseType
    nonce: str
    scope: str
    state: str
    code_challenge: str
    code_challenge_method: str

    @staticmethod
    def get_allowed_scopes():
        return ["openid", constants.SCOPE_AUTHORIZATION_BY_PROXY]

    @property
    def splitted_scopes(self):
        return self.scope.split()

    @validator("scope")
    def validate_scopes(cls, scopes):  # pylint: disable=no-self-argument
        splitted_scopes = scopes.split()
        for scope in splitted_scopes:
            if scope not in cls.get_allowed_scopes():
                log.warning(
                    "Scope %s not allowed, only %s are supported",
                    scope,
                    cls.get_allowed_scopes(),
                )

        return scopes

    @cached_property
    def authorization_by_proxy(self):
        return constants.SCOPE_AUTHORIZATION_BY_PROXY in self.splitted_scopes
