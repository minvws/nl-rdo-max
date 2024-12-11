from typing import List, Union

from pydantic import BaseModel


class NameUsageIndicator(BaseModel):
    code: str
    omschrijving: str


class BrpName(BaseModel):
    voornamen: Union[str, None] = None
    voorvoegsel: Union[str, None] = None
    geslachtsnaam: Union[str, None] = None
    voorletters: Union[str, None] = None
    volledigeNaam: Union[str, None] = None
    aanduidingNaamgebruik: Union[NameUsageIndicator, None] = None


class BrpPersonDTO(BaseModel):
    naam: BrpName
    leeftijd: Union[int, None] = None


class BrpPersonsResponseDTO(BaseModel):
    type: str
    personen: List[BrpPersonDTO]


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
    first_name: Union[str, None] = None
    prefix: Union[str, None] = None
    last_name: Union[str, None] = None
    initials: Union[str, None] = None
    full_name: Union[str, None] = None

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
    age: Union[int, None] = None
    name: NameDTO

    @staticmethod
    def from_brp_person(brp_person: BrpPersonDTO) -> "PersonDTO":
        return PersonDTO(
            age=brp_person.leeftijd, name=NameDTO.from_brp_name(brp_person.naam)
        )


# https://brp-api.github.io/Haal-Centraal-BRP-bevragen/v2/redoc#tag/Personen/operation/Personen
class BrpRequest(BaseModel):
    burgerservicenummer: Union[str, int]
    type: str = "RaadpleegMetBurgerservicenummer"
