from typing import Dict, Any

from app.misc.utils import file_content_raise_if_none
from app.services.encryption.jwe_service import JweService
from app.services.encryption.xed25519_jwe_service import XEd25519JweService
from app.services.userinfo.userinfo_service import UserinfoService


class CCUserinfoService(UserinfoService):
    def __init__(self, jwe_service: JweService, clients: dict, app_mode: str):
        self._jwe_service = jwe_service
        self._clients = clients
        self._app_mode = app_mode

    def request_userinfo_for_artifact(
        self,
        acs_context: Dict[str, Any],
        resolved_artifact: Dict[str, Any],
    ) -> str:
        if self._app_mode == "legacy":
            # noinspection PyTypeChecker
            service: XEd25519JweService = self._jwe_service  # type:ignore
            return service.box_encrypt(
                resolved_artifact["bsn"],
                self._clients[acs_context["client_id"]]["client_public_nacl_key"],
            )
        content = file_content_raise_if_none(
            self._clients[acs_context["client_id"]]["client_certificate_path"]
        )
        return self._jwe_service.to_jwe(
            {"bsn": resolved_artifact["bsn"]},  # type:ignore
            content,
        )
