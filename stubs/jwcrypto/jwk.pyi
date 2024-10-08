from _typeshed import Incomplete
from enum import Enum
from jwcrypto.common import JWException as JWException, base64url_decode as base64url_decode, base64url_encode as base64url_encode, json_decode as json_decode, json_encode as json_encode
from typing import NamedTuple

class UnimplementedOKPCurveKey:
    @classmethod
    def generate(cls) -> None: ...
    @classmethod
    def from_public_bytes(cls, *args) -> None: ...
    @classmethod
    def from_private_bytes(cls, *args) -> None: ...

ImplementedOkpCurves: Incomplete
Ed25519PublicKey = UnimplementedOKPCurveKey
Ed25519PrivateKey = UnimplementedOKPCurveKey
Ed448PublicKey = UnimplementedOKPCurveKey
Ed448PrivateKey = UnimplementedOKPCurveKey
priv_bytes: Incomplete
X25519PublicKey = UnimplementedOKPCurveKey
X25519PrivateKey = UnimplementedOKPCurveKey
X448PublicKey = UnimplementedOKPCurveKey
X448PrivateKey = UnimplementedOKPCurveKey

class _Ed25519_CURVE(NamedTuple):
    pubkey: Incomplete
    privkey: Incomplete

class _Ed448_CURVE(NamedTuple):
    pubkey: Incomplete
    privkey: Incomplete

class _X25519_CURVE(NamedTuple):
    pubkey: Incomplete
    privkey: Incomplete

class _X448_CURVE(NamedTuple):
    pubkey: Incomplete
    privkey: Incomplete

JWKTypesRegistry: Incomplete

class ParmType(Enum):
    name: str
    b64: str
    b64u: str
    unsupported: str

class JWKParameter(NamedTuple):
    description: Incomplete
    public: Incomplete
    required: Incomplete
    type: Incomplete

JWKValuesRegistry: Incomplete
JWKParamsRegistry: Incomplete
JWKEllipticCurveRegistry: Incomplete
JWKUseRegistry: Incomplete
JWKOperationsRegistry: Incomplete
JWKpycaCurveMap: Incomplete
IANANamedInformationHashAlgorithmRegistry: Incomplete

class InvalidJWKType(JWException):
    value: Incomplete
    def __init__(self, value: Incomplete | None = None) -> None: ...

class InvalidJWKUsage(JWException):
    value: Incomplete
    use: Incomplete
    def __init__(self, use, value) -> None: ...

class InvalidJWKOperation(JWException):
    op: Incomplete
    values: Incomplete
    def __init__(self, operation, values) -> None: ...

class InvalidJWKValue(JWException): ...

class JWK(dict):
    def __init__(self, **kwargs) -> None: ...
    @classmethod
    def generate(cls, **kwargs): ...
    def generate_key(self, **params) -> None: ...
    def import_key(self, **kwargs) -> None: ...
    @classmethod
    def from_json(cls, key): ...
    def export(self, private_key: bool = True, as_dict: bool = False): ...
    def export_public(self, as_dict: bool = False): ...
    def export_private(self, as_dict: bool = False): ...
    def export_symmetric(self, as_dict: bool = False): ...
    def public(self): ...
    @property
    def has_public(self): ...
    @property
    def has_private(self): ...
    @property
    def is_symmetric(self): ...
    @property
    def key_type(self): ...
    @property
    def key_id(self): ...
    @property
    def key_curve(self): ...
    def get_curve(self, arg): ...
    def get_op_key(self, operation: Incomplete | None = None, arg: Incomplete | None = None): ...
    def import_from_pyca(self, key) -> None: ...
    def import_from_pem(self, data, password: Incomplete | None = None, kid: Incomplete | None = None) -> None: ...
    def export_to_pem(self, private_key: bool = False, password: bool = False): ...
    @classmethod
    def from_pyca(cls, key): ...
    @classmethod
    def from_pem(cls, data, password: Incomplete | None = None): ...
    def thumbprint(self, hashalg=...): ...
    def thumbprint_uri(self, hname: str = 'sha-256'): ...
    def __setitem__(self, item, value) -> None: ...
    def update(self, *args, **kwargs) -> None: ...
    def setdefault(self, key, default: Incomplete | None = None): ...
    def __delitem__(self, item) -> None: ...
    def __eq__(self, other): ...
    def __hash__(self): ...
    def __getattr__(self, item): ...
    def __setattr__(self, item, value) -> None: ...
    @classmethod
    def from_password(cls, password): ...

class _JWKkeys(set):
    def add(self, elem) -> None: ...

class JWKSet(dict):
    def __init__(self, *args, **kwargs) -> None: ...
    def __iter__(self): ...
    def __contains__(self, key) -> bool: ...
    def __setitem__(self, key, val) -> None: ...
    def update(self, *args, **kwargs) -> None: ...
    def setdefault(self, key, default: Incomplete | None = None): ...
    def add(self, elem) -> None: ...
    def export(self, private_keys: bool = True, as_dict: bool = False): ...
    def import_keyset(self, keyset) -> None: ...
    @classmethod
    def from_json(cls, keyset): ...
    def get_key(self, kid): ...
    def get_keys(self, kid): ...
