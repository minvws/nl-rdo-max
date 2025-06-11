from pydantic import BaseModel

class KvkAddress(BaseModel):
    street: str
    house_number: str
    postal_code: str
    city: str
    country: str

class KvkAttributes(BaseModel):
    name: str
    date_of_registration: str
    status: str
    legal_form: str
    address: KvkAddress
