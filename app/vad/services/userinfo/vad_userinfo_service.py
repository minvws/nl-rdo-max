import asyncio
import json

import inject

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
        bsn_exchanger: BsnExchanger,
    ) -> None:
        self.bsn_exchanger: BsnExchanger = bsn_exchanger

    def request_userinfo_for_digid_artifact(
        self,
        authentication_context: AuthenticationContext,
        artifact_response: ArtifactResponse,
        subject_identifier: str,
    ) -> str:
        bsn = artifact_response.get_bsn(authorization_by_proxy=True)
        user_data: UserInfoDTO = asyncio.run(self.bsn_exchanger.exchange(bsn))
        return json.dumps(user_data.model_dump())

    def request_userinfo_for_exchange_token(
        self, authentication_context: AuthenticationContext, subject_identifier: str
    ) -> str:
        raise NotImplementedError()
