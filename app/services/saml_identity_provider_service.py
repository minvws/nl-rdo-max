import json

from jinja2 import Environment, FileSystemLoader, select_autoescape
from app.models.saml.saml_identity_provider import SamlIdentityProvider


class SamlIdentityProviderService():

    def __init__(
        self,
        identity_providers_path: str,
        templates_path: str
    ):

        jinja_env = Environment(
            loader=FileSystemLoader(templates_path),
            autoescape=select_autoescape(),
        )

        self._identity_providers = self._parse_identity_providers(identity_providers_path, jinja_env)

    def get_identity_provider(self, identity_provider_name: str):
        """
        Get ID provider from parsed identity_providers_file
        """
        if identity_provider_name in self._identity_providers:
            return self._identity_providers[identity_provider_name]
        raise ValueError(f"Provider not known: {identity_provider_name}, please check your configs.")


    def _parse_identity_providers(self, identity_providers_path: str, jinja_env: Environment) -> dict:
        with open(identity_providers_path, "r", encoding="utf-8") as identity_providers_file:
            identity_providers = json.loads(identity_providers_file.read())

        providers = {}
        for provider in identity_providers.keys():
            providers[provider] = SamlIdentityProvider(
                provider, identity_providers[provider], jinja_env
            )

        return providers
