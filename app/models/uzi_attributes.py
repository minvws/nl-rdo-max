from pydantic import BaseModel
from typing import List


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
    relations: List[Relation]
