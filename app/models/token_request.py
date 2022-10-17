from typing import Union

from pydantic import BaseModel, validator
import html
from urllib.parse import parse_qs

from pydantic.error_wrappers import ValidationError


class TokenRequest(BaseModel):
    grant_type: str
    code: str
    redirect_uri: str
    code_verifier: str
    client_id: str
    query_string: str

    # pylint: disable=invalid-name
    # noinspection PyPep8Naming
    @classmethod
    def from_body_query_string(
            cls,
            query_string
    ) -> "TokenRequest":
        parsed = dict((k, v[0]) for k, v in parse_qs(query_string).items())
        parsed["query_string"] = query_string
        try:
            return TokenRequest.parse_obj(
                parsed
            )
        except ValidationError as validation_error:
            errors = [error["loc"][0] for error in validation_error.errors()]
            keys = ""
            if len(errors) == 1:
                keys = errors[0]
            elif len(errors) > 1:
                keys = ', '.join(errors[:-1]) + ' and ' + errors[len(errors) - 1]
            raise ValueError(
                f"Expects {keys} to be contained in the urlencoded body of the request"
            )
