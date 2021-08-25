import json

from typing import Dict

from .id_provider import IdProvider
from ..config import settings

# pylint: disable=too-few-public-methods
class Provider:
    ID_PROVIDERS_PATH = settings.saml.identity_provider_settings

    def __init__(self) -> None:
        self.id_providers = self._parse_id_providers()

    def _parse_id_providers(self) -> Dict[str, IdProvider]:
        with open(self.ID_PROVIDERS_PATH, 'r') as id_providers_file:
            id_providers = json.loads(id_providers_file.read())

        providers = {}
        for provider in id_providers.keys():
            providers[provider] = IdProvider(provider, id_providers[provider])

        return providers

    def get_id_provider(self, name):
        if name in self.id_providers:
            return self.id_providers[name]
        raise ValueError("Provider not known: {}, please check your configs.")
