from typing import List

from pydantic import BaseModel


class Relation(BaseModel):
    ura: str
    entity_name: str
    roles: List[str]


class UziAttributes(BaseModel):
    initials: str
    surname_prefix: str
    surname: str
    loa_authn: str
    loa_uzi: str
    uzi_id: str
    relations: List[Relation]
