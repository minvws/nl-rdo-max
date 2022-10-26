def random(size: int) -> bytes: ...

class EncryptedMessage(bytes):
    """
    A bytes subclass that holds a messaged that has been encrypted by a
    :class:`SecretBox`.
    """

    @classmethod
    def _from_parts(cls, nonce: bytes, ciphertext: bytes, combined: bytes) -> None: ...
    @property
    def nonce(self) -> bytes: ...
    @property
    def ciphertext(self) -> bytes: ...
