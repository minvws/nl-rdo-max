from abc import ABC, abstractmethod

import inject
from jose import jwe as jwe_module

from app.vad.brp.schemas import PersonDTO
from app.vad.brp.service import BrpService
from app.vad.prs.repositories import PrsRepository
from app.vad.prs.schemas import PrsResponseData

from .repositories import KeyRepository
from .schemas import UserInfoDTO


class JweFactory(ABC):
    @abstractmethod
    def create_jwe(self, data: str) -> str: ...  # pragma: no cover


class JoseJweFactory(JweFactory):
    @inject.autoparams()
    def __init__(self, key_repository: KeyRepository):
        self._encryption_key: bytes = key_repository.get_jwe_encryption_key()

    def create_jwe(self, data: str) -> str:
        jwe: str = jwe_module.encrypt(data, key=self._encryption_key, algorithm="dir")
        return jwe


class NoOpJweFactory(JweFactory):
    def __init__(self) -> None:
        pass

    def create_jwe(self, data: str) -> str:
        return str(data)


class BsnExchanger:
    @inject.autoparams()
    def __init__(
        self,
        prs_repository: PrsRepository,
        brp_service: BrpService,
    ) -> None:
        self._prs_repository: PrsRepository = prs_repository
        self._brp_service: BrpService = brp_service

    async def exchange(self, bsn: str) -> UserInfoDTO:
        reference_pseudonym: PrsResponseData = await self._prs_repository.get_pseudonym(bsn)
        person: PersonDTO = await self._brp_service.get_person_info(bsn)

        return UserInfoDTO(reference_pseudonym=reference_pseudonym, person=person)
