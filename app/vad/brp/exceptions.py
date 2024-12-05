from http.client import HTTPException

from .schemas import BrpPersonResponseError


class BrpHttpRequestException(HTTPException): ...


class BrpHttpResponseException(HTTPException):
    def __init__(self, status_code: int, detail: BrpPersonResponseError) -> None:
        super().__init__(status_code, detail)
