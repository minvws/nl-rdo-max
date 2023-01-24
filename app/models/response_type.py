from enum import Enum


class ResponseType(str, Enum):
    CODE: str = "code"

    def __str__(self) -> str:  # pylint: disable=invalid-str-returned
        return self.CODE
