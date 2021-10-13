import json
from typing import Tuple

from functools import cached_property

from packaging.version import Version
from packaging.version import parse as version_parse

from ..config import Settings
from .metadata import IdPMetadata, SPMetadata
from .utils import from_settings

class IdProvider:

    def __init__(self, settings: Settings, name, idp_setting, jinja_env) -> None:
        self.name = name
        self.saml_spec_version = version_parse(str(idp_setting['saml_specification_version']))
        self.base_dir = idp_setting['base_dir']
        self.cert_path = idp_setting['cert_path']
        self.key_path = idp_setting['key_path']
        self.settings_path = idp_setting['settings_path']
        self.idp_metadata_path = idp_setting['idp_metadata_path']

        with open(self.settings_path, 'r', encoding='utf-8') as settings_file:
            self.settings_dict = json.loads(settings_file.read())

        with open(self.key_path, 'r', encoding='utf-8') as key_file:
            self.priv_key = key_file.read()

        self._idp_metadata = IdPMetadata(self.idp_metadata_path)
        self._sp_metadata = SPMetadata(settings, self.settings_dict, self.keypair_paths, jinja_env)

    @cached_property
    def authn_binding(self):
        return from_settings(self.settings_dict, 'idp.singleSignOnService.binding')

    @property
    def keypair_paths(self) -> Tuple[str, str]:
        return (self.cert_path, self.key_path)

    @property
    def sp_metadata(self) -> SPMetadata:
        return self._sp_metadata

    @property
    def idp_metadata(self) -> IdPMetadata:
        return self._idp_metadata

    @property
    def saml_is_new_version(self):
        return self.saml_spec_version >= Version("4.4")

    @property
    def saml_is_legacy_version(self):
        return self.saml_spec_version == Version("3.5")
