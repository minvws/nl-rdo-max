import logging
from functools import cached_property
from typing import Union

from pydantic import BaseModel, validator

from app import constants
from app.models.response_type import ResponseType

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
    login_hint: Union[str, None] = None

    @staticmethod
    def get_allowed_scopes():
        return ["openid", constants.SCOPE_AUTHORIZATION_BY_PROXY]

    @property
    def splitted_scopes(self):
        return self.scope.split()

    @property
    def login_hints(self):
        if self.login_hint is None:
            return []
        return self.login_hint.split(",")

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
