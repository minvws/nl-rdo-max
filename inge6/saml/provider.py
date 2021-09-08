import json

from typing import Dict

from .id_provider import IdProvider
from ..config import settings

# pylint: disable=too-few-public-methods
class Provider:
    """
    Given a path to the identity provider settings, parse all identity providers.

    Required settings:
        - settings.saml.identity_provider_settings, path to the configuration for all identity providers.
    """
    ID_PROVIDERS_PATH = settings.saml.identity_provider_settings

    def __init__(self) -> None:
<<<<<<< HEAD
        self.id_providers = self._parse_id_providers()

    def _parse_id_providers(self) -> Dict[str, IdProvider]:
        with open(self.ID_PROVIDERS_PATH, 'r') as id_providers_file:
            id_providers = json.loads(id_providers_file.read())
=======
        with open(self.SETTINGS_PATH, 'r', encoding='utf-8') as settings_file:
            self.settings_dict = json.loads(settings_file.read())

        with open(self.PRIV_KEY_PATH, 'r', encoding='utf-8') as key_file:
            self.priv_key = key_file.read()
>>>>>>> f12e4d641fd4b4bbd1491e698364e34ec0c080c1

        providers = {}
        for provider in id_providers.keys():
            providers[provider] = IdProvider(provider, id_providers[provider])

        return providers

    def get_id_provider(self, name):
        if name in self.id_providers:
            return self.id_providers[name]
        raise ValueError("Provider not known: {}, please check your configs.")
