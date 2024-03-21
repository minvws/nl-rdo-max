from typing import Optional

from starlette.responses import Response


class AuthorizeResponse:
    response: Response
    session_id: Optional[str]

    def __init__(
        self,
        response: Response,
        session_id: Optional[str] = None,
    ):
        self.response = response
        self.session_id = session_id
