from _typeshed import Incomplete
from abc import ABCMeta, abstractmethod
from jwcrypto.common import InvalidCEKeyLength as InvalidCEKeyLength, InvalidJWAAlgorithm as InvalidJWAAlgorithm, InvalidJWEKeyLength as InvalidJWEKeyLength, InvalidJWEKeyType as InvalidJWEKeyType, InvalidJWEOperation as InvalidJWEOperation, base64url_decode as base64url_decode, base64url_encode as base64url_encode, json_decode as json_decode
from jwcrypto.jwk import JWK as JWK

default_max_pbkdf2_iterations: int

class JWAAlgorithm(metaclass=ABCMeta):
    @property
    @abstractmethod
    def name(self): ...
    @property
    @abstractmethod
    def description(self): ...
    @property
    @abstractmethod
    def keysize(self): ...
    @property
    @abstractmethod
    def algorithm_usage_location(self): ...
    @property
    @abstractmethod
    def algorithm_use(self): ...
    @property
    def input_keysize(self): ...

class _RawJWS:
    def sign(self, key, payload) -> None: ...
    def verify(self, key, payload, signature) -> None: ...

class _RawHMAC(_RawJWS):
    backend: Incomplete
    hashfn: Incomplete
    def __init__(self, hashfn) -> None: ...
    def sign(self, key, payload): ...
    def verify(self, key, payload, signature) -> None: ...

class _RawRSA(_RawJWS):
    padfn: Incomplete
    hashfn: Incomplete
    def __init__(self, padfn, hashfn) -> None: ...
    def sign(self, key, payload): ...
    def verify(self, key, payload, signature) -> None: ...

class _RawEC(_RawJWS):
    hashfn: Incomplete
    def __init__(self, curve, hashfn) -> None: ...
    @property
    def curve(self): ...
    def sign(self, key, payload): ...
    def verify(self, key, payload, signature) -> None: ...

class _RawNone(_RawJWS):
    def sign(self, key, payload): ...
    def verify(self, key, payload, signature) -> None: ...

class _HS256(_RawHMAC, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str
    def __init__(self) -> None: ...

class _HS384(_RawHMAC, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str
    def __init__(self) -> None: ...

class _HS512(_RawHMAC, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str
    def __init__(self) -> None: ...

class _RS256(_RawRSA, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str
    def __init__(self) -> None: ...

class _RS384(_RawRSA, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str
    def __init__(self) -> None: ...

class _RS512(_RawRSA, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str
    def __init__(self) -> None: ...

class _ES256(_RawEC, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str
    def __init__(self) -> None: ...

class _ES256K(_RawEC, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str
    def __init__(self) -> None: ...

class _ES384(_RawEC, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str
    def __init__(self) -> None: ...

class _ES512(_RawEC, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str
    def __init__(self) -> None: ...

class _PS256(_RawRSA, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str
    def __init__(self) -> None: ...

class _PS384(_RawRSA, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str
    def __init__(self) -> None: ...

class _PS512(_RawRSA, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str
    def __init__(self) -> None: ...

class _None(_RawNone, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str

class _RawKeyMgmt:
    def wrap(self, key, bitsize, cek, headers) -> None: ...
    def unwrap(self, key, bitsize, ek, headers) -> None: ...

class _RSA(_RawKeyMgmt):
    padfn: Incomplete
    def __init__(self, padfn) -> None: ...
    def wrap(self, key, bitsize, cek, headers): ...
    def unwrap(self, key, bitsize, ek, headers): ...

class _Rsa15(_RSA, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str
    def __init__(self) -> None: ...
    def unwrap(self, key, bitsize, ek, headers): ...

class _RsaOaep(_RSA, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str
    def __init__(self) -> None: ...

class _RsaOaep256(_RSA, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str
    def __init__(self) -> None: ...

class _AesKw(_RawKeyMgmt):
    keysize: Incomplete
    backend: Incomplete
    def __init__(self) -> None: ...
    def wrap(self, key, bitsize, cek, headers): ...
    def unwrap(self, key, bitsize, ek, headers): ...

class _A128KW(_AesKw, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str

class _A192KW(_AesKw, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str

class _A256KW(_AesKw, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str

class _AesGcmKw(_RawKeyMgmt):
    keysize: Incomplete
    backend: Incomplete
    def __init__(self) -> None: ...
    def wrap(self, key, bitsize, cek, headers): ...
    def unwrap(self, key, bitsize, ek, headers): ...

class _A128GcmKw(_AesGcmKw, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str

class _A192GcmKw(_AesGcmKw, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str

class _A256GcmKw(_AesGcmKw, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str

class _Pbes2HsAesKw(_RawKeyMgmt):
    name: Incomplete
    keysize: Incomplete
    hashsize: Incomplete
    backend: Incomplete
    aeskwmap: Incomplete
    def __init__(self) -> None: ...
    def wrap(self, key, bitsize, cek, headers): ...
    def unwrap(self, key, bitsize, ek, headers): ...

class _Pbes2Hs256A128Kw(_Pbes2HsAesKw, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str
    hashsize: int

class _Pbes2Hs384A192Kw(_Pbes2HsAesKw, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str
    hashsize: int

class _Pbes2Hs512A256Kw(_Pbes2HsAesKw, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str
    hashsize: int

class _Direct(_RawKeyMgmt, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str
    def wrap(self, key, bitsize, cek, headers): ...
    def unwrap(self, key, bitsize, ek, headers): ...

class _EcdhEs(_RawKeyMgmt, JWAAlgorithm):
    name: str
    description: str
    algorithm_usage_location: str
    algorithm_use: str
    keysize: Incomplete
    backend: Incomplete
    aeskwmap: Incomplete
    def __init__(self) -> None: ...
    def wrap(self, key, bitsize, cek, headers): ...
    def unwrap(self, key, bitsize, ek, headers): ...

class _EcdhEsAes128Kw(_EcdhEs):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str

class _EcdhEsAes192Kw(_EcdhEs):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str

class _EcdhEsAes256Kw(_EcdhEs):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str

class _EdDsa(_RawJWS, JWAAlgorithm):
    name: str
    description: str
    algorithm_usage_location: str
    algorithm_use: str
    keysize: Incomplete
    def sign(self, key, payload): ...
    def verify(self, key, payload, signature): ...

class _RawJWE:
    def encrypt(self, k, aad, m) -> None: ...
    def decrypt(self, k, aad, iv, e, t) -> None: ...

class _AesCbcHmacSha2(_RawJWE):
    keysize: Incomplete
    backend: Incomplete
    hashfn: Incomplete
    blocksize: Incomplete
    wrap_key_size: Incomplete
    def __init__(self, hashfn) -> None: ...
    def encrypt(self, k, aad, m): ...
    def decrypt(self, k, aad, iv, e, t): ...

class _A128CbcHs256(_AesCbcHmacSha2, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str
    def __init__(self) -> None: ...

class _A192CbcHs384(_AesCbcHmacSha2, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str
    def __init__(self) -> None: ...

class _A256CbcHs512(_AesCbcHmacSha2, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str
    def __init__(self) -> None: ...

class _AesGcm(_RawJWE):
    keysize: Incomplete
    backend: Incomplete
    wrap_key_size: Incomplete
    def __init__(self) -> None: ...
    def encrypt(self, k, aad, m): ...
    def decrypt(self, k, aad, iv, e, t): ...

class _A128Gcm(_AesGcm, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str

class _A192Gcm(_AesGcm, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str

class _A256Gcm(_AesGcm, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str

class _BP256R1(_RawEC, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str
    def __init__(self) -> None: ...

class _BP384R1(_RawEC, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str
    def __init__(self) -> None: ...

class _BP512R1(_RawEC, JWAAlgorithm):
    name: str
    description: str
    keysize: int
    algorithm_usage_location: str
    algorithm_use: str
    def __init__(self) -> None: ...

class JWA:
    algorithms_registry: Incomplete
    @classmethod
    def instantiate_alg(cls, name, use: Incomplete | None = None): ...
    @classmethod
    def signing_alg(cls, name): ...
    @classmethod
    def keymgmt_alg(cls, name): ...
    @classmethod
    def encryption_alg(cls, name): ...
