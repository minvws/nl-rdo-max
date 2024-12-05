from logging import Logger

import inject

from .exceptions import BrpHttpRequestException, BrpHttpResponseException
from .repositories import BrpRepository
from .schemas import BrpName, BrpPersonDTO, BrpPersonsResponseDTO, PersonDTO


class BrpService:
    @inject.autoparams()
    def __init__(
        self,
        brp_repository: BrpRepository,
        logger: Logger,
    ) -> None:
        self._brp_repository: BrpRepository = brp_repository
        self.logger: Logger = logger

    async def get_person_info(self, bsn: str) -> PersonDTO:
        try:
            brp_persons_dto: BrpPersonsResponseDTO = await self._brp_repository.find(bsn)
            self.validate_response(brp_persons_dto)

        except BrpHttpRequestException as e:
            self.logger.error(f"Request error while requesting person info from BRP: {e}")
            return self.create_empty_person_dto()

        except BrpHttpResponseException as e:
            self.logger.error(f"Response error while requesting person info from BRP: {e}")
            return self.create_empty_person_dto()

        brp_person_dto: BrpPersonDTO = brp_persons_dto.personen[0]
        return PersonDTO.from_brp_person(brp_person=brp_person_dto)

    def validate_response(self, brp_persons_dto: BrpPersonsResponseDTO) -> None:
        if len(brp_persons_dto.personen) == 0:
            raise Exception("No person found")

        if len(brp_persons_dto.personen) > 1:
            raise Exception("Multiple persons found")

    def create_empty_person_dto(self) -> PersonDTO:
        return PersonDTO.from_brp_person(brp_person=BrpPersonDTO(naam=BrpName()))
