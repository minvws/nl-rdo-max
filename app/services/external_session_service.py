from typing import Dict, Any

import requests

from app.exceptions.max_exceptions import UnauthorizedError
from app.services.encryption.jwt_service import JWTService

ALG = "RS256"


class ExternalSessionService:
    def __init__(
        self,
        session_url: str,
        session_jwt_issuer: str,
        session_jwt_audience: str,
        external_http_requests_timeout_seconds: int,
        jwt_service: JWTService,
    ) -> None:
        self._session_url = session_url
        self._session_jwt_issuer = session_jwt_issuer
        self._session_jwt_audience = session_jwt_audience
        self._external_http_requests_timeout_seconds = (
            external_http_requests_timeout_seconds
        )
        self._jwt_service = jwt_service

    def create_session(
        self, claims: Dict[str, Any], session_type: str
    ) -> Dict[str, str]:
        jwt = self._jwt_service.create_jwt(
            {
                **claims,
                "iss": self._session_jwt_issuer,
                "aud": self._session_jwt_audience,
            }
        )
        external_server_response = requests.post(
            f"{self._session_url}",
            headers={"Content-Type": "text/plain", "Authorization": f"Bearer {jwt}"},
            timeout=self._external_http_requests_timeout_seconds,
        )
        if external_server_response.status_code >= 400:
            raise UnauthorizedError(
                log_message=f"Error while fetching {session_type} Response, {session_type} server returned: "
                f"{external_server_response.status_code}, {external_server_response.text}",
                error_description="Unable to create external session",
            )

        return {"exchange_token": external_server_response.json()}

    def get_session_status(self, exchange_token: str) -> str:
        jwt = self._jwt_service.create_jwt(
            {
                "iss": self._session_jwt_issuer,
                "aud": self._session_jwt_audience,
                "exchange_token": exchange_token,
            }
        )
        session_status = requests.get(
            f"{self._session_url}/status",
            headers={
                "Content-Type": "text/plain",
                "Authorization": f"Bearer {jwt}",
            },
            timeout=self._external_http_requests_timeout_seconds,
        )

        if session_status.status_code != 200:
            raise UnauthorizedError(error_description="Authentication Failed")

        return session_status.json()
