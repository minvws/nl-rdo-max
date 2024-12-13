from pydantic import BaseModel, Field


class PrsResponseData(BaseModel):
    rid: str = Field(description="Reference ID")
    pdn: str = Field(description="Pseudonym")


class Pdn(BaseModel):
    data: str = Field(description="Pseudonym")


class Rid(BaseModel):
    data: str = Field(description="Reference ID")
