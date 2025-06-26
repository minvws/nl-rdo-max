import pytest
from lxml import etree
from app.misc.saml_utils import (
    to_soap_envelope,
    find_element_text_if_not_none,
    status_from_value,
    status_from_element,
)


def test_to_soap_envelope():
    # Create a simple XML node
    node = etree.Element("TestElement")
    node.text = "Hello"

    # Wrap it in a SOAP envelope
    envelope = to_soap_envelope(node)

    # Check the structure
    assert envelope.tag.endswith("Envelope")
    body = envelope.find("{http://www.w3.org/2003/05/soap-envelope}Body")
    assert body is not None
    # The body should contain our node
    assert body[0].tag == "TestElement"
    assert body[0].text == "Hello"


def test_find_element_text_if_not_none():
    root = etree.Element("root")
    child = etree.SubElement(root, "child")
    child.text = "value"
    assert find_element_text_if_not_none(root, "child") == "value"
    assert find_element_text_if_not_none(None, "child") is None


def test_status_from_value_success():
    el = etree.Element("StatusCode", Value="urn:oasis:names:tc:SAML:2.0:status:Success")
    assert status_from_value(el) == "Success"

    el = etree.Element(
        "{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode",
        Value="urn:oasis:names:tc:SAML:2.0:status:Success",
    )
    assert status_from_value(el) == "Success"


def test_status_from_element_custom():
    el = etree.Element("StatusCode", Value="urn:custom:status:MyStatus")
    assert status_from_element(el) == "MyStatus"


def test_status_from_element_nested():
    el = etree.Element(
        "{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode",
        Value="urn:oasis:names:tc:SAML:2.0:status:Responder",
    )
    inner = etree.SubElement(
        el,
        "{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode",
        Value="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
    )
    assert status_from_element(el) == "AuthnFailed"
