from typing import Optional, Any
from nacl.utils import EncryptedMessage

class SecretBox(object):

    KEY_SIZE: int
    NONCE_SIZE: int
    MACBYTES: int
    MESSAGEBYTES_MAX: int
    def __init__(self, key: bytes, encoder: Any = ...): ...
    def encrypt(self, plaintext: bytes, nonce: Optional[bytes] = None, encoder: Any = ...) -> EncryptedMessage: ...
    def decrypt(self, ciphertext: bytes, nonce: Optional[bytes] = None, encoder: Any = ...) -> bytes: ...