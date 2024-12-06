from logging import Logger

import pytest
from pytest_mock import MockerFixture

from app.vad.brp.repositories import ApiBrpRepository
from app.vad.brp.schemas import (
    BrpName,
    BrpPersonDTO,
    BrpPersonsResponseDTO,
    NameUsageIndicator,
    PersonDTO,
)
from app.vad.brp.service import BrpService


class TestBrpApiHandling:
    @pytest.fixture
    def mock_brp_repository(self, mocker: MockerFixture) -> ApiBrpRepository:
        mock_brp_repo: ApiBrpRepository = mocker.Mock(ApiBrpRepository)
        return mock_brp_repo

    @pytest.fixture
    def brp_service(self, mocker: MockerFixture, mock_brp_repository: ApiBrpRepository) -> BrpService:
        mock_brp_service: BrpService = BrpService(brp_repository=mock_brp_repository, logger=mocker.Mock(Logger))
        return mock_brp_service

    @pytest.mark.asyncio
    async def test_find(
        self, brp_service: BrpService, mock_brp_repository: ApiBrpRepository, mocker: MockerFixture
    ) -> None:
        bsn = "123456789"
        person_data = BrpPersonDTO(
            naam=BrpName(
                voornamen="John",
                geslachtsnaam="Doe",
                voorletters="J.",
                volledigeNaam="John Doe",
                aanduidingNaamgebruik=NameUsageIndicator(code="E", omschrijving="eigen geslachtsnaam"),
            ),
            leeftijd=46,
        )
        response_data = BrpPersonsResponseDTO(personen=[person_data], type="RaadpleegMetBurgerservicenummer")
        mock_brp_repository_find = mocker.patch.object(mock_brp_repository, "find")
        mock_brp_repository_find.return_value = response_data

        result = await brp_service.get_person_info(bsn)
        expected_result = PersonDTO.from_brp_person(brp_person=person_data)
        assert result == expected_result

    @pytest.mark.asyncio
    async def test_find_raises_exception_when_no_person_was_found(
        self, brp_service: BrpService, mock_brp_repository: ApiBrpRepository, mocker: MockerFixture
    ) -> None:
        bsn = "123456789"
        response_data = BrpPersonsResponseDTO(personen=[], type="RaadpleegMetBurgerservicenummer")
        mock_brp_repository_find = mocker.patch.object(mock_brp_repository, "find")
        mock_brp_repository_find.return_value = response_data

        with pytest.raises(Exception, match="No person found"):
            await brp_service.get_person_info(bsn)

    @pytest.mark.asyncio
    async def test_find_raises_exception_when_multiple_persons_were_found(
        self, brp_service: BrpService, mock_brp_repository: ApiBrpRepository, mocker: MockerFixture
    ) -> None:
        bsn = "123456789"
        person_data_1 = BrpPersonDTO(
            naam=BrpName(
                voornamen="John",
                geslachtsnaam="Doe",
                voorletters="J.",
                volledigeNaam="John Doe",
                aanduidingNaamgebruik=NameUsageIndicator(code="E", omschrijving="eigen geslachtsnaam"),
            ),
            leeftijd=46,
        )
        person_data_2 = BrpPersonDTO(
            naam=BrpName(
                voornamen="Jane",
                geslachtsnaam="Doe",
                voorletters="J.",
                volledigeNaam="John Doe",
                aanduidingNaamgebruik=NameUsageIndicator(code="E", omschrijving="eigen geslachtsnaam"),
            ),
            leeftijd=45,
        )
        response_data = BrpPersonsResponseDTO(
            personen=[person_data_1, person_data_2], type="RaadpleegMetBurgerservicenummer"
        )
        mock_brp_repository_find = mocker.patch.object(mock_brp_repository, "find")
        mock_brp_repository_find.return_value = response_data

        with pytest.raises(Exception, match="Multiple persons found"):
            await brp_service.get_person_info(bsn)

    @pytest.mark.asyncio
    async def test_find_can_return_deceased_person(
        self, brp_service: BrpService, mock_brp_repository: ApiBrpRepository, mocker: MockerFixture
    ) -> None:
        bsn = "123456789"
        person_data = BrpPersonDTO(
            naam=BrpName(
                voornamen="John",
                geslachtsnaam="Doe",
                voorletters="J.",
                volledigeNaam="John Doe",
                aanduidingNaamgebruik=NameUsageIndicator(code="E", omschrijving="eigen geslachtsnaam"),
            ),
        )
        response_data = BrpPersonsResponseDTO(personen=[person_data], type="RaadpleegMetBurgerservicenummer")
        mock_brp_repository_find = mocker.patch.object(mock_brp_repository, "find")
        mock_brp_repository_find.return_value = response_data

        result: PersonDTO = await brp_service.get_person_info(bsn)
        expected_result: PersonDTO = PersonDTO.from_brp_person(brp_person=person_data)
        assert result == expected_result

    @pytest.mark.asyncio
    async def test_find_can_return_person_without_age(
        self, brp_service: BrpService, mock_brp_repository: ApiBrpRepository, mocker: MockerFixture
    ) -> None:
        bsn = "123456789"
        person_data = BrpPersonDTO(
            naam=BrpName(
                voornamen="John",
                geslachtsnaam="Doe",
                voorletters="J.",
                volledigeNaam="John Doe",
                aanduidingNaamgebruik=NameUsageIndicator(code="E", omschrijving="eigen geslachtsnaam"),
            ),
        )
        response_data = BrpPersonsResponseDTO(personen=[person_data], type="RaadpleegMetBurgerservicenummer")
        mock_brp_repository_find = mocker.patch.object(mock_brp_repository, "find")
        mock_brp_repository_find.return_value = response_data

        result: PersonDTO = await brp_service.get_person_info(bsn)
        expected_result: PersonDTO = PersonDTO.from_brp_person(brp_person=person_data)
        assert result == expected_result
