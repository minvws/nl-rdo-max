from app.storage.authentication_cache import AuthenticationCache
from fastapi import Request, Response
from pyop.provider import extract_bearer_token_from_http_request
from pyop.provider import Provider as PyopProvider


class UziProvider():
    def __init__(
            self,
            authentication_cache: AuthenticationCache,
            pyop_provider: PyopProvider,
    ):
        self._authentication_cache = authentication_cache
        self._pyop_provider = pyop_provider

