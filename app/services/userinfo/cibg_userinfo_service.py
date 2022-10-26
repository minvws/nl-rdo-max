from typing import Dict, Any

from app.misc.utils import file_content_raise_if_none
from app.services.encryption.jwe_service import JweService
from app.services.userinfo.userinfo_service import UserinfoService


class CIBGUserinfoService(UserinfoService):
    def __init__(self):
        pass

    def request_userinfo_for_artifact(
        self, acs_context: Dict[str, Any], resolved_artifact: Dict[str, Any]
    ) -> str:
        raise Exception("unimplemented")


class MockedCIBGUserinfoService(CIBGUserinfoService):
    def __init__(self, jwe_service: JweService, clients: dict):
        super().__init__()
        self._jwe_service = jwe_service
        self._clients = clients

    def request_userinfo_for_artifact(
        self, acs_context: Dict[str, Any], resolved_artifact: Dict[str, Any]
    ) -> str:
        if not resolved_artifact["mocking"]:
            return super().request_userinfo_for_artifact(acs_context, resolved_artifact)
        return self._jwe_service.to_jwe(
            {
                "uraNumber": self._clients[acs_context["client_id"]]["external_id"],
                "uziNumber": resolved_artifact["bsn"],
                "roleCodes": ["01.041", "30.000", "01.010", "01.011"],
                "givenName": "givenName",
                "surName": "surName",
            },
            file_content_raise_if_none(
                self._clients[acs_context["client_id"]]["client_certificate_path"]
            ),
        )
