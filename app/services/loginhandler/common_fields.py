import logging
from typing import Any, Dict

from jwcrypto.jwk import JWK

from app.misc.utils import file_content_raise_if_none
from app.services.encryption.jwe_service_provider import JweServiceProvider
from app.services.response_factory import ResponseFactory

logger = logging.getLogger(__name__)


class CommonFields:
    def __init__(
        self,
        jwe_service_provider: JweServiceProvider,
        response_factory: ResponseFactory,
        session_url: str,
        clients: Dict[str, Any],
        session_jwt_issuer: str,
        session_jwt_audience: str,
        jwt_sign_priv_key_path: str,
        jwt_sign_crt_path: str,
        external_http_requests_timeout_seconds: int,
    ):
        self._jwe_service_provider = jwe_service_provider
        self._response_factory = response_factory
        self._session_url = session_url
        self._clients = clients
        self._session_jwt_issuer = session_jwt_issuer
        self._session_jwt_audience = session_jwt_audience
        jwt_sign_priv_key = file_content_raise_if_none(jwt_sign_priv_key_path)
        jwt_sign_crt = file_content_raise_if_none(jwt_sign_crt_path)
        self._private_sign_jwk_key = JWK.from_pem(jwt_sign_priv_key.encode("utf-8"))
        self._public_sign_jwk_key = JWK.from_pem(jwt_sign_crt.encode("utf-8"))
        self._external_http_requests_timeout_seconds = (
            external_http_requests_timeout_seconds
        )
