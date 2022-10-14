import abc


#todo: Define interface with pubkey from client ed25519 and rsa typed
from typing import Union, Dict


class JweService(abc.ABC):
    pass

    @abc.abstractmethod
    def to_jwe(self, data: Dict[str, str], pubkey: Union[str, None] = None):
        pass