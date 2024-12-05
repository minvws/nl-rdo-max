from typing import List

from pydantic import BaseModel


class NameUsageIndicator(BaseModel):
    code: str
    omschrijving: str


class BrpName(BaseModel):
    voornamen: str | None = None
    voorvoegsel: str | None = None
    geslachtsnaam: str | None = None
    voorletters: str | None = None
    volledigeNaam: str | None = None
    aanduidingNaamgebruik: NameUsageIndicator | None = None


class BrpPersonDTO(BaseModel):
    naam: BrpName
    leeftijd: int | None = None


class BrpPersonsResponseDTO(BaseModel):
    type: str
    personen: list[BrpPersonDTO]


class InvalidParam(BaseModel):
    name: str
    code: str
    reason: str


class BrpPersonResponseError(BaseModel):
    invalidParams: List[InvalidParam]
    type: str
    title: str
    status: int
    detail: str
    instance: str
    code: str


# VAD Response models
class NameDTO(BaseModel):
    first_name: str | None = None
    prefix: str | None = None
    last_name: str | None = None
    initials: str | None = None
    full_name: str | None = None

    @staticmethod
    def from_brp_name(brp_name: BrpName) -> "NameDTO":
        return NameDTO(
            first_name=brp_name.voornamen,
            prefix=brp_name.voorvoegsel,
            last_name=brp_name.geslachtsnaam,
            initials=brp_name.voorletters,
            full_name=brp_name.volledigeNaam,
        )


class PersonDTO(BaseModel):
    age: int | None
    name: NameDTO

    @staticmethod
    def from_brp_person(brp_person: BrpPersonDTO) -> "PersonDTO":
        return PersonDTO(age=brp_person.leeftijd, name=NameDTO.from_brp_name(brp_person.naam))


# https://brp-api.github.io/Haal-Centraal-BRP-bevragen/v2/redoc#tag/Personen/operation/Personen
class BrpRequest(BaseModel):
    burgerservicenummer: str | int
    type: str = "RaadpleegMetBurgerservicenummer"
