from abc import ABC, abstractmethod
from typing import Union

import httpx

from .exceptions import BrpHttpRequestException, BrpHttpResponseException

from .schemas import (
    BrpName,
    BrpPersonDTO,
    BrpPersonResponseError,
    BrpPersonsResponseDTO,
    NameUsageIndicator,
)


class BrpRepository(ABC):
    @abstractmethod
    async def find(self, bsn: str) -> BrpPersonsResponseDTO: ...  # pragma: no cover


class MockBrpRepository(BrpRepository):
    async def find(self, bsn: str) -> BrpPersonsResponseDTO:
        return BrpPersonsResponseDTO(
            type="RaadpleegMetBurgerservicenummer",
            personen=[
                BrpPersonDTO(
                    leeftijd=42,
                    naam=BrpName(
                        voornamen="Jan",
                        voorvoegsel="van",
                        geslachtsnaam="Jansen",
                        voorletters="J.",
                        volledigeNaam="Jan van Jansen",
                        aanduidingNaamgebruik=NameUsageIndicator(
                            code="E", omschrijving="eigen geslachtsnaam"
                        ),
                    ),
                )
            ],
        )


class ApiBrpRepository(BrpRepository):
    def __init__(self, base_url: str, api_key: Union[str, None] = None) -> None:
        self.base_url = base_url
        self.api_key: str | None = api_key

    async def find(self, bsn: str) -> BrpPersonsResponseDTO:
        url = f"{self.base_url}/personen"
        payload = {
            "type": "RaadpleegMetBurgerservicenummer",
            "burgerservicenummer": [bsn],
            "fields": ["naam", "leeftijd"],
        }
        headers: dict[str, str] = {"Content-Type": "application/json"}

        if self.api_key:
            headers["X-API-KEY"] = self.api_key

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(url, json=payload, headers=headers)
                response.raise_for_status()
                data = response.json()
                return BrpPersonsResponseDTO.model_validate(data)
        except httpx.HTTPStatusError as exc:
            error_response = BrpPersonResponseError(**exc.response.json())
            raise BrpHttpResponseException(
                status_code=exc.response.status_code, detail=error_response
            ) from exc
        except httpx.RequestError as exc:
            raise BrpHttpRequestException(
                500,
                {
                    "error": "Error occurred while making request to BRP API",
                    "error_description": str(exc),
                },
            ) from exc
