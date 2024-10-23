# pylint: disable=c-extension-no-member
import datetime
import secrets
from typing import Dict, Optional, List

import xmlsec
from lxml import etree

from app.misc.saml_utils import (
    get_loc_bind,
    has_valid_signatures,
    compute_keyname,
    enforce_cert_newlines,
)
from .constants import NAMESPACES
from .saml_request import SAMLRequest
from ...misc.utils import strip_cert


class SPMetadata(SAMLRequest):
    """
    Ability to generate metadata needed for IDPs. It uses the template defined in the template path.

    Required settings:
        - settings.saml.sp_template, path to the sp metadata template
        - settings.issuer, name of the issuer
    """

    TEMPLATE_NAME = "sp_metadata.xml.jinja"
    CLUSTER_TEMPLATE_NAME = "sp_metadata.clustered.xml.jinja"
    DELTA_DAYS_VALID_UNTIL = 365

    def __init__(self, settings, keypair_sign, jinja_env) -> None:
        """
        Initialize SPMetadata using the settings in the settings dict, for idp_name. And sign it
        using the keypair_sign, which is also the pair used for receiving encrypted material.

        :param settings: dictionary containing the settings for the SP
        :param keypair_sign: paths to the private and public key for signing and signature validation
        :param pubkey_enc: (OPTIONAL) path to the public key the IdP should use for XML encryption, useful when
        decryption of the messages is done by another party. Otherwise, same key as for signing is used.
        """
        super().__init__(keypair_sign)

        self.jinja_env = jinja_env
        self.settings = settings

        self.dv_keynames: List[str] = []

        self.clustered = "cluster_settings" in settings
        self._root = etree.fromstring(self.render_template())

        with open(self.signing_cert_path, "r", encoding="utf-8") as cert_file:
            cert_data = cert_file.read()

        self.root.find(
            ".//ds:Signature/ds:KeyInfo//ds:X509Certificate", NAMESPACES
        ).text = strip_cert(cert_data)

        self.root.find(".//ds:Signature/ds:KeyInfo//ds:KeyName", NAMESPACES).text = (
            compute_keyname(cert_data)
        )

        self.sign(self.root, self._id_hash)

    @property
    def sp_settings(self):
        return self.settings.get("sp", {})

    @property
    def cluster_settings(self):
        return self.settings.get("cluster_settings", {})

    @property
    def connections(self):
        return self.cluster_settings.get("connections", [])

    @property
    def authorization_by_proxy_scopes(self):
        return self.settings.get("security", {}).get("authorizationByProxyScopes", [])

    @property
    def authorization_by_proxy_request_ids(self):
        return self.settings.get("security", {}).get(
            "authorizationByProxyRequestIds", []
        )

    @property
    def default_scopes(self):
        return self.settings.get("security", {}).get("defaultScopes", [])

    @property
    def requested_authn_context(self):
        return self.settings.get("security", {}).get("requestedAuthnContext", [])

    @property
    def requested_authn_context_comparison(self):
        return self.settings.get("security", {}).get(
            "requestedAuthnContextComparison", "exact"
        )

    @property
    def root(self):
        return self._root

    @property
    def entity_id(self):
        return self.sp_settings.get("entityId", "")

    @property
    def issuer_id(self):
        return self.entity_id

    @property
    def service_uuid(self):
        try:
            return self.sp_settings["attributeConsumingService"]["requestedAttributes"][
                0
            ]["attributeValue"][0]
        except KeyError as key_error:
            raise KeyError(
                "key does not exist. please check your settings.json"
            ) from key_error

    @property
    def service_name(self):
        return self.sp_settings["attributeConsumingService"]["serviceName"]

    @property
    def service_desc(self):
        return self.sp_settings["attributeConsumingService"]["serviceDescription"]

    @property
    def acs_url(self):
        return self.sp_settings["assertionConsumerService"]["url"]

    @property
    def acs_binding(self):
        return self.sp_settings["assertionConsumerService"]["binding"]

    def get_cert_data(self, cluster_name: Optional[str]):
        if cluster_name is None:
            # When cluster name is none, we want the certs of our service.
            cert_path = self.signing_cert_path
        else:
            cert_path = self.connections.get(cluster_name, {}).get("cert_path")

        with open(cert_path, "r", encoding="utf-8") as cert_file:
            cert_data = cert_file.read()

        return cert_data

    def get_spsso(self, cluster_name: Optional[str]):
        cert = self.get_cert_data(cluster_name)
        keyname = compute_keyname(cert)
        self.dv_keynames.append(keyname)
        return {
            "cert": strip_cert(cert),
            "keyname": keyname,
            "acs_binding": self.acs_binding,
            "acs_url": self.acs_url,
        }

    def create_entity_descriptor(self, cluster_name: Optional[str]):
        return {
            "id": "_" + secrets.token_hex(41),  # total length 42.
            "entity_id": (
                self.entity_id
                if cluster_name is None
                else self.connections.get(cluster_name, {}).get("entity_id")
            ),
            "spsso": self.get_spsso(cluster_name),
        }

    def create_cluster_entity_descriptor(self):
        return {
            "clustered_" + cluster_name: self.create_entity_descriptor(cluster_name)
            for cluster_name in self.connections
        }

    def render_clustered_template(self):
        with open(
            self.cluster_settings["tls_keypath"], "r", encoding="utf-8"
        ) as tls_keyfile:
            cert_tls = tls_keyfile.read()

        keyname_tls = compute_keyname(cert_tls)

        template = self.jinja_env.get_template(self.CLUSTER_TEMPLATE_NAME)
        clustered_context = {
            "id": self._id_hash,
            "valid_until": (
                datetime.datetime.utcnow()
                + datetime.timedelta(days=self.DELTA_DAYS_VALID_UNTIL)
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "dv_descriptors": self.create_cluster_entity_descriptor(),
            "lc_descriptor": self.create_entity_descriptor(None),
            "cert_tls": strip_cert(cert_tls),
            "keyname_tls": keyname_tls,
        }

        return template.render(clustered_context)

    def render_unclustered_template(self):
        template = self.jinja_env.get_template(self.TEMPLATE_NAME)
        unclustered_context = {
            "id": self._id_hash,
            "entity_id": self.entity_id,
            "spsso": self.get_spsso(None),
            "service_name": self.service_name,
            "service_desc": self.service_desc,
            "service_uuid": self.service_uuid,
            "valid_until": (
                datetime.datetime.utcnow()
                + datetime.timedelta(days=self.DELTA_DAYS_VALID_UNTIL)
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

        return template.render(unclustered_context)

    def render_template(self) -> str:
        if self.clustered:
            return self.render_clustered_template()

        return self.render_unclustered_template()

    def _valid_signature(self) -> bool:
        signing_certificates = {}
        with open(self.signing_cert_path, "r", encoding="utf-8") as cert_file:
            cert = cert_file.read()
            keyname = compute_keyname(cert)
            signing_certificates[keyname] = cert

        _, is_valid = has_valid_signatures(
            self.root, signing_certificates=signing_certificates
        )
        return is_valid

    def _contains_keyname(self):
        return self.root.find(".//ds:KeyInfo/ds:KeyName", NAMESPACES) is not None

    def _has_correct_bindings(self) -> bool:
        correct_bindings = True
        sls_elem = self.root.find(".//md:SingleLogoutService", NAMESPACES)
        acs_elem = self.root.find(".//md:AssertionConsumerService", NAMESPACES)

        if sls_elem is not None:
            correct_bindings = (
                correct_bindings
                and sls_elem.attrib["Binding"]
                == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            )

        # Required element.
        correct_bindings = (
            correct_bindings
            and acs_elem.attrib["Binding"]
            == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
        )

        return correct_bindings

    def validate(self) -> list:
        errors = []

        if self.clustered is False:
            if self.root.tag != f"{{{NAMESPACES['md']}}}EntityDescriptor":
                errors.append("Root is not an EntityDescriptor")

            if len(self.root.findall(".//md:SPSSODescriptor", NAMESPACES)) != 1:
                errors.append("Only one SPSSO Descriptor allowed")
        else:
            if self.root.tag != f"{{{NAMESPACES['md']}}}EntitiesDescriptor":
                errors.append("Root is not an EntitiesDescriptor")

        if not self._has_correct_bindings():
            errors.append("Incorrect bindings for SPSSO services")

        if not self._contains_keyname():
            errors.append("Does not contain a keyname in KeyDescriptor")

        if not self._valid_signature():
            errors.append("Invalid Signature")

        return errors


class IdPMetadata:
    def __init__(self, idp_metadata_path) -> None:
        self.template = etree.parse(idp_metadata_path).getroot()
        new_root, valid_sign = has_valid_signatures(
            self.template, signing_certificates=self.get_signing_certificates()
        )
        if not valid_sign:
            raise xmlsec.VerificationError("Signature is invalid")

        self.template = new_root

        self.entity_id = self.template.attrib["entityID"]

    def find_in_md(self, name: str):
        return self.template.find(
            f".//md:{name}", {"md": "urn:oasis:names:tc:SAML:2.0:metadata"}
        )

    def get_artifact_rs(self) -> Dict[str, str]:
        resolution_service = self.find_in_md("ArtifactResolutionService")
        return get_loc_bind(resolution_service)

    def get_signing_certificates(self) -> Dict[str, str]:
        signing_certificates = {}
        for key_descriptor in self.template.findall(
            ".//md:IDPSSODescriptor//md:KeyDescriptor", NAMESPACES
        ):
            if key_descriptor.attrib.get("use") == "signing":
                keyname = key_descriptor.find(".//dsig:KeyName", NAMESPACES).text
                cert_data = key_descriptor.find(
                    ".//dsig:X509Certificate", NAMESPACES
                ).text
                cert = enforce_cert_newlines(cert_data)
                signing_certificates[keyname] = (
                    f"""-----BEGIN CERTIFICATE-----\n{cert}\n-----END CERTIFICATE-----"""
                )
        return signing_certificates

    def get_sso(self, binding="POST") -> Dict[str, str]:
        sso = self.template.find(
            f".//md:SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-{binding}']",
            {"md": "urn:oasis:names:tc:SAML:2.0:metadata"},
        )
        return get_loc_bind(sso)

    def get_xml(self) -> bytes:
        return etree.tostring(self.template)
