from abc import ABC, abstractmethod

import inject

from app.vad.brp.schemas import PersonDTO
from app.vad.brp.service import BrpService
from app.vad.prs.repositories import PrsRepository
from app.vad.prs.schemas import PrsResponseData

from .schemas import UserInfoDTO

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
