import json

import httpx
import pytest
from pytest_mock import MockerFixture

from app.vad.brp.repositories import ApiBrpRepository, MockBrpRepository
from app.vad.brp.schemas import BrpPersonsResponseDTO


class TestMockBrpRepository:
    @pytest.mark.asyncio
    async def test_mock_brp_repository_find_with_str_bsn(self) -> None:
        repository: MockBrpRepository = MockBrpRepository()
        bsn: str = "123456789"
        result: BrpPersonsResponseDTO = await repository.find(bsn)

        assert isinstance(result, BrpPersonsResponseDTO)
        assert result.personen[0].naam.voornamen == "Jan"
        assert result.personen[0].naam.voorletters == "J."
        assert result.personen[0].naam.voorvoegsel == "van"
        assert result.personen[0].naam.geslachtsnaam == "Jansen"
        assert result.personen[0].naam.volledigeNaam == "Jan van Jansen"
        assert result.personen[0].leeftijd == 42


class TestApiBrpRepository:
    @pytest.mark.asyncio
    async def test_find_person_receives_empty_response_from_brp_api(self, mocker: MockerFixture) -> None:
        base_url = "https://api.example.com"
        bsn = "123456789"
        brp_api_response = {"type": "RaadpleegMetBurgerservicenummer", "personen": []}

        mock_post = mocker.patch.object(
            httpx.AsyncClient, "post", return_value=mocker.Mock(status_code=200, json=lambda: brp_api_response)
        )

        repository = ApiBrpRepository(base_url=base_url)
        result = await repository.find(bsn)

        assert result == BrpPersonsResponseDTO.model_validate(brp_api_response)
        mock_post.assert_called_once_with(
            f"{base_url}/personen",
            json={
                "type": "RaadpleegMetBurgerservicenummer",
                "burgerservicenummer": [bsn],
                "fields": ["naam", "leeftijd"],
            },
            headers={
                "Content-Type": "application/json",
            },
        )

    @pytest.mark.asyncio
    async def test_find_person_info(self, mocker: MockerFixture) -> None:
        base_url = "https://api.example.com"
        api_key = "test_api_key"
        bsn = "987654321"
        brp_api_response = {
            "type": "RaadpleegMetBurgerservicenummer",
            "personen": [
                {
                    "naam": {
                        "aanduidingNaamgebruik": {"code": "E", "omschrijving": "eigen geslachtsnaam"},
                        "voornamen": "Suzanne",
                        "geslachtsnaam": "Moulin",
                        "voorletters": "S.",
                        "volledigeNaam": "Suzanne Moulin",
                    },
                    "leeftijd": 38,
                }
            ],
        }

        mock_post = mocker.patch.object(
            httpx.AsyncClient, "post", return_value=mocker.Mock(status_code=200, json=lambda: brp_api_response)
        )

        repository = ApiBrpRepository(base_url=base_url, api_key=api_key)
        result = await repository.find(bsn)

        assert result == BrpPersonsResponseDTO.model_validate(brp_api_response)
        mock_post.assert_called_once_with(
            f"{base_url}/personen",
            json={
                "type": "RaadpleegMetBurgerservicenummer",
                "burgerservicenummer": [bsn],
                "fields": ["naam", "leeftijd"],
            },
            headers={"Content-Type": "application/json", "X-API-KEY": api_key},
        )

    @pytest.mark.asyncio
    async def test_find_person_info_without_age(self, mocker: MockerFixture) -> None:
        base_url = "https://api.example.com"
        api_key = "test_api_key"
        bsn = "123456789"
        valid_response = {
            "type": "RaadpleegMetBurgerservicenummer",
            "personen": [
                {
                    "naam": {
                        "aanduidingNaamgebruik": {"code": "E", "omschrijving": "eigen geslachtsnaam"},
                        "voornamen": "Evert",
                        "geslachtsnaam": "Eizenga",
                        "voorletters": "E.",
                        "volledigeNaam": "Evert Eizenga",
                    },
                }
            ],
        }

        mock_post = mocker.patch.object(
            httpx.AsyncClient, "post", return_value=mocker.Mock(status_code=200, json=lambda: valid_response)
        )

        repository = ApiBrpRepository(base_url=base_url, api_key=api_key)
        result = await repository.find(bsn)

        assert result == BrpPersonsResponseDTO.model_validate_json(json.dumps(valid_response))
        mock_post.assert_called_once_with(
            f"{base_url}/personen",
            json={
                "type": "RaadpleegMetBurgerservicenummer",
                "burgerservicenummer": [bsn],
                "fields": ["naam", "leeftijd"],
            },
            headers={"Content-Type": "application/json", "X-API-KEY": api_key},
        )
