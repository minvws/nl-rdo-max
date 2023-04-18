import json
import logging
import os

from typing import Dict

from jinja2 import Environment, FileSystemLoader, select_autoescape
from app.models.saml.saml_identity_provider import SamlIdentityProvider


log = logging.getLogger(__name__)


class SamlIdentityProviderService:
    def __init__(
        self,
        identity_providers_base_path: str,
        templates_path: str,
        external_http_requests_timeout_seconds: int,
    ):
        jinja_env = Environment(
            loader=FileSystemLoader(templates_path),
            autoescape=select_autoescape(),
        )

        self._identity_providers = (
            SamlIdentityProviderService._parse_identity_providers(
                identity_providers_base_path,
                jinja_env,
                external_http_requests_timeout_seconds,
            )
        )

    def get_identity_provider(
        self, identity_provider_name: str
    ) -> SamlIdentityProvider:
        """
        Get ID provider from parsed identity_providers_file
        """
        if identity_provider_name in self._identity_providers:
            return self._identity_providers[identity_provider_name]
        raise ValueError(
            f"Provider not known: {identity_provider_name}, please check your configs."
        )

    @staticmethod
    def _parse_identity_providers(
        identity_providers_base_path: str,
        jinja_env: Environment,
        external_http_requests_timeout_seconds: int,
    ) -> Dict[str, SamlIdentityProvider]:
        providers = {}
        for folder_name in os.listdir(identity_providers_base_path):
            try:
                full_folder_path = os.path.join(
                    identity_providers_base_path, folder_name
                )
                if (
                    os.path.isdir(full_folder_path)
                    and "." not in folder_name
                    and folder_name != "templates"
                ):
                    with open(
                        os.path.join(full_folder_path, "settings.json"),
                        "r",
                        encoding="utf-8",
                    ) as idp_settings:
                        providers[folder_name] = SamlIdentityProvider(
                            folder_name,
                            identity_providers_base_path + "/" + folder_name,
                            json.loads(idp_settings.read()),
                            jinja_env,
                            external_http_requests_timeout_seconds=external_http_requests_timeout_seconds,
                        )
            except Exception as err:  # pylint: disable=broad-except
                log.warning(
                    "Unable to instantiate SamlIdentityProvider for %s with error: %s",
                    os.path.join(
                        os.path.join(identity_providers_base_path, folder_name),
                        "settings.json",
                    ),
                    err,
                )
                log.exception(err)
        return providers
