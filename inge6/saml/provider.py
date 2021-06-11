import json

from .metadata import IdPMetadata, SPMetadata
from ..config import settings

class Provider:
    SETTINGS_PATH = settings.saml.settings_path
    PRIV_KEY_PATH = settings.saml.key_path

    def __init__(self) -> None:
        with open(self.SETTINGS_PATH, 'r') as settings_file:
            self.settings_dict = json.loads(settings_file.read())

        with open(self.PRIV_KEY_PATH, 'r') as key_file:
            self.priv_key = key_file.read()

        self._idp_metadata = IdPMetadata()
        self._sp_metadata = SPMetadata()

    @property
    def sp_metadata(self) -> SPMetadata:
        return self._sp_metadata

    @property
    def idp_metadata(self) -> IdPMetadata:
        return self._idp_metadata
