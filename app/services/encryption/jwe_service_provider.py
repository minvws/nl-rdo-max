from typing import Dict
from app.exceptions.max_exceptions import ServerErrorException
from app.services.encryption.jwe_service import JweService
from app.services.encryption.rsa_jwe_service import RSAJweService
from app.services.encryption.xed25519_jwe_service import XEd25519JweService


class JweServiceProvider:
    def __init__(self, config: Dict[str, str]):
        self._jwe_services: Dict[str, JweService] = {}
        if "rsa" in config["services"].split(","):
            self._jwe_services["rsa"] = RSAJweService(
                config["jwe_sign_priv_key_path"],
                config["jwe_sign_crt_path"],
            )
        if "x25519" in config["services"]:
            self._jwe_services["x25519"] = XEd25519JweService(
                config["jwe_sign_nacl_priv_key"],
            )

    def get_jwe_service(self, key_type: str) -> JweService:
        lower_key_type = key_type.lower()
        if lower_key_type not in self._jwe_services:
            raise ServerErrorException(
                error_description=f"JweService for keytype {lower_key_type} not found"
            )
        return self._jwe_services[lower_key_type]
