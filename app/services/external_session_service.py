from typing import Dict

import requests

from app.exceptions.max_exceptions import UnauthorizedError

ALG = "RS256"


class ExternalSessionService:
    def __init__(
        self, session_url: str, external_http_requests_timeout_seconds: int
    ) -> None:
        self._session_url = session_url
        self._external_http_requests_timeout_seconds = (
            external_http_requests_timeout_seconds
        )

    def create_session(self, jwt: str, session_type: str) -> Dict[str, str]:
        external_server_response = requests.post(
            f"{self._session_url}",
            headers={"Content-Type": "text/plain"},
            data=jwt,
            timeout=self._external_http_requests_timeout_seconds,
        )
        if external_server_response.status_code >= 400:
            raise UnauthorizedError(
                log_message=f"Error while fetching {session_type} Response, {session_type} server returned: "
                f"{external_server_response.status_code}, {external_server_response.text}",
                error_description="Unable to create UZI session",
            )

        return {"exchange_token": external_server_response.json()}

    def get_session_status(self, token_jwt: str) -> str:
        session_status = requests.get(
            f"{self._session_url}/status",
            headers={
                "Content-Type": "text/plain",
                "Authorization": f"Bearer {token_jwt}",
            },
            timeout=self._external_http_requests_timeout_seconds,
        )

        if session_status.status_code != 200:
            raise UnauthorizedError(error_description="Authentication Failed")

        return session_status.json()
