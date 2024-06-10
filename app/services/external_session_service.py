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

    def get_exchange_token(self, jwt: str) -> Dict[str, str]:
        uzi_response = requests.post(
            f"{self._session_url}",
            headers={"Content-Type": "text/plain"},
            data=jwt,
            timeout=self._external_http_requests_timeout_seconds,
        )
        if uzi_response.status_code >= 400:
            raise UnauthorizedError(
                log_message="Error while fetching UziResponse, Uzi server returned: "
                f"{uzi_response.status_code}, {uzi_response.text}",
                error_description="Unable to create UZI session",
            )

        return {"exchange_token": uzi_response.json()}

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
