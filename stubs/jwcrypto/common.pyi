from _typeshed import Incomplete
from collections.abc import MutableMapping
from typing import NamedTuple

def base64url_encode(payload): ...
def base64url_decode(payload): ...
def json_encode(string): ...
def json_decode(string): ...

class JWException(Exception): ...

class InvalidJWAAlgorithm(JWException):
    def __init__(self, message: Incomplete | None = None) -> None: ...

class InvalidCEKeyLength(JWException):
    def __init__(self, expected, obtained) -> None: ...

class InvalidJWEOperation(JWException):
    def __init__(self, message: Incomplete | None = None, exception: Incomplete | None = None) -> None: ...

class InvalidJWEKeyType(JWException):
    def __init__(self, expected, obtained) -> None: ...

class InvalidJWEKeyLength(JWException):
    def __init__(self, expected, obtained) -> None: ...

class InvalidJWSERegOperation(JWException):
    def __init__(self, message: Incomplete | None = None, exception: Incomplete | None = None) -> None: ...

class JWKeyNotFound(JWException):
    def __init__(self, message: Incomplete | None = None) -> None: ...

class JWSEHeaderParameter(NamedTuple):
    description: Incomplete
    mustprotect: Incomplete
    supported: Incomplete
    check_fn: Incomplete

class JWSEHeaderRegistry(MutableMapping):
    def __init__(self, init_registry: Incomplete | None = None) -> None: ...
    def check_header(self, h, value): ...
    def __getitem__(self, key): ...
    def __iter__(self): ...
    def __delitem__(self, key) -> None: ...
    def __setitem__(self, h, jwse_header_param) -> None: ...
    def __len__(self) -> int: ...
