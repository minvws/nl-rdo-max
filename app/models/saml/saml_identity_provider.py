import json
from typing import Tuple

from functools import cached_property

from packaging.version import Version
from packaging.version import parse as version_parse

from app.models.saml.saml_request import ArtifactResolveRequest, AuthNRequest
from app.models.saml.metadata import IdPMetadata, SPMetadata
from app.models.saml.exceptions import ScopingAttributesNotAllowed


class SamlIdentityProvider:  # pylint: disable=too-many-instance-attributes
    def __init__(self, name, idp_setting, jinja_env) -> None:
        self.name = name
        self.saml_spec_version = version_parse(
            str(idp_setting["saml_specification_version"])
        )
        self.base_dir = idp_setting["base_dir"]
        self.cert_path = idp_setting["cert_path"]
        self.key_path = idp_setting["key_path"]
        self.settings_path = idp_setting["settings_path"]
        self.advanced_settings_path = idp_setting["advanced_settings_path"]
        self.idp_metadata_path = idp_setting["idp_metadata_path"]

        self.jinja_env = jinja_env
        with open(self.settings_path, "r", encoding="utf-8") as settings_file:
            self.settings_dict = json.loads(settings_file.read())
        with open(
            self.advanced_settings_path, "r", encoding="utf-8"
        ) as adv_settings_file:
            self.settings_dict.update(json.loads(adv_settings_file.read()))

        with open(self.key_path, "r", encoding="utf-8") as key_file:
            self.priv_key = key_file.read()

        self._idp_metadata = IdPMetadata(self.idp_metadata_path)
        self._sp_metadata = SPMetadata(
            self.settings_dict, self.keypair_paths, self.jinja_env
        )

    @cached_property
    def authn_binding(self):
        return self.settings_dict["idp"]["singleSignOnService"]["binding"]

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

    def create_authn_request(self, authorization_by_proxy, cluster_name=None):
        scoping_list, request_ids = self.determine_scoping_attributes(
            authorization_by_proxy
        )
        sso_url = self.idp_metadata.get_sso()["location"]

        return AuthNRequest(
            sso_url,
            self.sp_metadata,
            self.jinja_env,
            scoping_list=scoping_list,
            request_ids=request_ids,
            cluster_name=cluster_name,
        )

    def create_artifactresolve_request(self, artifact: str):
        sso_url = self.idp_metadata.get_sso()["location"]
        return ArtifactResolveRequest(
            artifact, sso_url, self.sp_metadata, self.jinja_env
        )

    def determine_scoping_attributes(self, authorization_by_proxy):
        if self.sp_metadata.allow_scoping:
            return (
                self.determine_scoping_list(authorization_by_proxy),
                self.determine_request_ids(authorization_by_proxy),
            )

        if authorization_by_proxy:
            raise ScopingAttributesNotAllowed(
                "Scoping for this provider has been disabled in the settings"
            )
        return [], []

    def determine_scoping_list(self, authorization_by_proxy):
        if authorization_by_proxy:
            return self.sp_metadata.authorization_by_proxy_scopes
        return self.sp_metadata.default_scopes

    def determine_request_ids(self, authorization_by_proxy):
        if authorization_by_proxy:
            return self.sp_metadata.authorization_by_proxy_request_ids
        return []
