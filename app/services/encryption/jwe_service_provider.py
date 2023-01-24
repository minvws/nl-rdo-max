from app.exceptions.max_exceptions import ServerErrorException
from app.services.encryption.jwe_service import JweService


class JweServiceProvider:
    def __init__(self, **jwe_services: JweService):
        self._jwe_services = jwe_services

    def get_jwe_service(self, key_type: str) -> JweService:
        lower_key_type = key_type.lower()
        if lower_key_type not in self._jwe_services:
            raise ServerErrorException(
                error_description=f"JweService for keytype {lower_key_type} not found"
            )
        return self._jwe_services[lower_key_type]
