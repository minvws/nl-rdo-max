import logging
import time
from typing import Dict, Any, Optional, List


from app.misc.utils import (
    file_content_raise_if_none,
    mocked_kvk_value_to_kvk_data,
    strip_cert,
    mocked_bsn_to_uzi_data,
)
from app.models.authentication_context import AuthenticationContext
from app.models.saml.artifact_response import ArtifactResponse
from app.services.encryption.jwt_service_factory import JWTServiceFactory
from app.services.userinfo.userinfo_service import UserinfoService

log = logging.getLogger(__name__)


# pylint: disable=too-many-arguments, too-many-positional-arguments, too-many-instance-attributes
class EherkenningUserinfoService(UserinfoService):
    def __init__(
        self,
        jwt_service_factory: JWTServiceFactory,
        environment: str,
        clients: dict,
        userinfo_request_signing_priv_key_path: str,
        userinfo_request_signing_crt_path: str,
        req_issuer: str,
        jwt_expiration_duration: int,
        jwt_nbf_lag: int,
        external_base_url: str,
    ):
        self.jwt_service = jwt_service_factory.create(
            userinfo_request_signing_priv_key_path, userinfo_request_signing_crt_path
        )
        self._environment = environment
        self._clients = clients
        self._jwt_expiration_duration = jwt_expiration_duration
        self._jwt_nbf_lag = jwt_nbf_lag
        self._req_issuer = req_issuer
        self._external_base_url = external_base_url

    def request_userinfo_for_digid_artifact(
        self,
        authentication_context: AuthenticationContext,
        artifact_response: ArtifactResponse,
        subject_identifier: str,
    ) -> str:
        raise NotImplementedError(
            "EherkenningUserinfoService does not support request_userinfo_for_digid_artifact"
        )
    
    def request_userinfo_for_eherkenning_artifact(
        self,
        authentication_context: AuthenticationContext,
        artifact_response: ArtifactResponse,
        subject_identifier: str,
    ) -> str:
        client_id = authentication_context.authorization_request["client_id"]
        client = self._clients[client_id]
        if (
            not self._environment.startswith("prod") and authentication_context.authentication_method == "eherkenning_mock"
        ):
            return self._request_userinfo_for_mock_artifact(
                client_id=client_id,
                client=client,
                artifact_response=artifact_response,
                req_acme_tokens=authentication_context.req_acme_tokens,
                subject_identifier=subject_identifier,
            )
        

    def request_userinfo_for_exchange_token(
        self, authentication_context: AuthenticationContext, subject_identifier: str
    ) -> str:
        raise NotImplementedError(
            "EherkenningUserinfoService does not support request_userinfo_for_exchange_token"
        )

    def _request_userinfo_for_mock_artifact(
        self,
        client_id: str,
        client: Dict[str, Any],
        artifact_response: ArtifactResponse,
        req_acme_tokens: Optional[List[str]],
        subject_identifier: str,
    ) -> str:
        kvk = artifact_response.get_kvk(False)

        kvk_pubkey = file_content_raise_if_none(client["client_public_key_path"])

        kvk_number = kvk.split("-")[0]

        kvk_data = mocked_kvk_value_to_kvk_data(
            kvk_number
        )

        kvk_data.name = kvk.split("-")[1] or kvk_data.name

        data = {
            **kvk_data.model_dump(),
            "iss": self._req_issuer,
            "aud": client_id,
            "sub": subject_identifier,
            "json_schema": self._external_base_url + "/json_schema.json",
            "nbf": int(time.time()) - self._jwt_nbf_lag,
            "exp": int(time.time()) + self._jwt_expiration_duration,
            "x5c": strip_cert(kvk_pubkey),
        }
        if req_acme_tokens:
            data["acme_tokens"] = req_acme_tokens

        jwe_token = self.jwt_service.create_jwe(client["public_key"], data)

        return jwe_token
