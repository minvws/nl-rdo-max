from typing import Optional
from urllib.parse import parse_qs

from pydantic import BaseModel, ValidationError


class TokenRequest(BaseModel):
    grant_type: str
    code: str
    redirect_uri: str
    code_verifier: str
    client_id: str
    client_assertion_type: Optional[str] = None
    client_assertion: Optional[str] = None
    query_string: str

    # pylint: disable=invalid-name
    # noinspection PyPep8Naming
    @classmethod
    def from_body_query_string(cls, query_string) -> "TokenRequest":
        parsed = dict((k, v[0]) for k, v in parse_qs(query_string).items())
        parsed["query_string"] = query_string
        try:
            return TokenRequest.parse_obj(parsed)
        except ValidationError as validation_error:
            errors = [error["loc"][0] for error in validation_error.errors()]
            keys = ""
            if len(errors) == 1:
                keys = str(errors[0])
            elif len(errors) > 1:
                keys = (
                    ", ".join(str(errors[:-1])) + " and " + str(errors[len(errors) - 1])
                )
            raise ValueError(
                f"Expects {keys} to be contained in the urlencoded body of the request"
            ) from validation_error
