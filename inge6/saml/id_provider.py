import json
from typing import Tuple

from functools import cached_property

from .metadata import IdPMetadata, SPMetadata
from .utils import from_settings

class IdProvider:

    def __init__(self, name, idp_setting) -> None:
        self.name = name
        self.saml_spec_version = idp_setting['saml_specification_version']
        self.base_dir = idp_setting['base_dir']
        self.cert_path = idp_setting['cert_path']
        self.key_path = idp_setting['key_path']
        self.settings_path = idp_setting['settings_path']
        self.idp_metadata_path = idp_setting['idp_metadata_path']

        with open(self.settings_path, 'r') as settings_file:
            self.settings_dict = json.loads(settings_file.read())

        with open(self.key_path, 'r') as key_file:
            self.priv_key = key_file.read()

        self._idp_metadata = IdPMetadata(self.idp_metadata_path)
        self._sp_metadata = SPMetadata(self.settings_dict, self.keypair_paths, name)

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
