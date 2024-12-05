import json
import uuid

import inject
import requests
from requests import Response

from app.models.authentication_context import AuthenticationContext
from app.models.saml.artifact_response import ArtifactResponse
from app.services.encryption.jwt_service_factory import JWTServiceFactory
from app.services.userinfo.userinfo_service import UserinfoService
from app.vad.utils import resolve_instance
from app.vad.vad.schemas import UserInfoDTO
from app.vad.vad.service import BsnExchanger


class VadUserinfoService(UserinfoService):
    @inject.autoparams()
    def __init__(
        self,
        jwt_service_factory: JWTServiceFactory,
        userinfo_request_signing_priv_key_path: str,
        userinfo_request_signing_crt_path: str,
        req_issuer: str,
        clients: dict,
        bsn_exchanger: BsnExchanger,
    ) -> None:
        self._req_issuer = req_issuer
        # self.jwt_service = jwt_service_factory.create(
        #     jwt_private_key_path=userinfo_request_signing_priv_key_path, 
        #     jwt_signing_certificate_path=userinfo_request_signing_crt_path
        # )
        self.clients = clients
        self.bsn_exchanger: BsnExchanger = bsn_exchanger

    async def request_userinfo_for_digid_artifact(
        self,
        authentication_context: AuthenticationContext,
        artifact_response: ArtifactResponse,
        subject_identifier: str,
    ) -> dict:
        bsn = artifact_response.get_bsn(authorization_by_proxy=True)        
        user_data: UserInfoDTO = await self.bsn_exchanger.exchange(bsn)
        return user_data.dict()

    def request_userinfo_for_exchange_token(
        self, authentication_context: AuthenticationContext, subject_identifier: str
    ) -> str:
        raise NotImplementedError()