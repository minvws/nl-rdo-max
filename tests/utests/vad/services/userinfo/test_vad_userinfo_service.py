import pytest
from pyop.message import AuthorizationRequest
from pytest_mock import MockerFixture

from app.models.authentication_context import AuthenticationContext
from app.models.authentication_meta import AuthenticationMeta
from app.models.saml.artifact_response_mock import ArtifactResponseMock
from tests.utests.vad.utils import configure_bindings
from app.vad.services.userinfo.vad_userinfo_service import VadUserinfoService
from app.vad.vad.schemas import UserInfoDTO


class TestVadUserinfoService:
    def test_vad_request_userinfo_for_digid_artifact(
        self, mocker: MockerFixture
    ) -> None:
        configure_bindings()

        vad_userinfo_service = VadUserinfoService()

        authentication_context = AuthenticationContext(
            authorization_request=mocker.Mock(spec=AuthorizationRequest),
            authorization_by_proxy=True,
            authentication_method="method",
            authentication_state={},
            session_id="session_id",
            req_acme_tokens=None,
            authentication_meta=mocker.Mock(spec=AuthenticationMeta),
        )
        bsn = "123456789"
        artifact_response: ArtifactResponseMock = ArtifactResponseMock(
            artifact_response_str=bsn
        )
        subject_identifier: str = "subject_identifier"
        user_info_json: str = vad_userinfo_service.request_userinfo_for_digid_artifact(
            authentication_context, artifact_response, subject_identifier
        )
        user_info: UserInfoDTO = UserInfoDTO.model_validate_json(user_info_json)

        assert user_info.person.name.last_name == "Jansen"
        assert user_info.reference_pseudonym.rid is not None
        assert isinstance(user_info.reference_pseudonym.rid, str)
