import json

from typing import Dict

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .id_provider import IdProvider
from ..config import Settings

from .constants import ROOT_DIR

# pylint: disable=too-few-public-methods
class Provider:
    """
    Given a path to the identity provider settings, parse all identity providers.

    Required settings:
        - settings.saml.identity_provider_settings, path to the configuration for all identity providers.
    """
    SAML_TEMPLATES_PATH = ROOT_DIR + '/templates/saml/xml'

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.id_providers_path = self.settings.saml.identity_provider_settings

        self.jinja_env = Environment(
            loader=FileSystemLoader(self.SAML_TEMPLATES_PATH),
            autoescape=select_autoescape()
        )
        self.id_providers = self._parse_id_providers()

    def _parse_id_providers(self) -> Dict[str, IdProvider]:
        with open(self.id_providers_path, 'r', encoding='utf-8') as id_providers_file:
            id_providers = json.loads(id_providers_file.read())

        providers = {}
        for provider in id_providers.keys():
            providers[provider] = IdProvider(provider, id_providers[provider], self.jinja_env)

        return providers

    def get_id_provider(self, name):
        if name in self.id_providers:
            return self.id_providers[name]
        raise ValueError("Provider not known: {}, please check your configs.")
