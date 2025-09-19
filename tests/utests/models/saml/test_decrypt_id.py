"""
Unit tests for the ArtifactResponse.decrypt_id method.
"""

import re

import pytest
from unittest.mock import MagicMock, patch
from lxml import etree

from app.models.saml.artifact_response import ArtifactResponse


@pytest.fixture
def mock_artifact_response():
    """Create a mocked ArtifactResponse instance."""
    # Create a mock for sp_metadata
    mock_sp_metadata = MagicMock()
    mock_sp_metadata.entity_id = "entity_id_1"
    mock_sp_metadata.clustered = False
    mock_sp_metadata.sign_keyname = "keyname1"

    # Create the main ArtifactResponse mock
    artifact_response = MagicMock(spec=ArtifactResponse)
    artifact_response.strict = True
    artifact_response._sp_metadata = mock_sp_metadata

    # Set up the allowed_recipients property to use the real implementation
    type(artifact_response).allowed_recipients = property(
        lambda self: (
            [self._sp_metadata.entity_id]
            if not self._sp_metadata.clustered
            else [conn.entity_id for conn in self._sp_metadata.connections]
            + [self._sp_metadata.entity_id]
        )
    )

    # Mock the internal decryption methods
    artifact_response._decrypt_enc_key.return_value = b"mock_aes_key"
    artifact_response._decrypt_enc_data.return_value = b"<NameID>test-id</NameID>"

    # Use the real decrypt_id method
    artifact_response.decrypt_id = ArtifactResponse.decrypt_id.__get__(
        artifact_response
    )
    artifact_response.log = MagicMock()

    return artifact_response


def test_decrypt_id_success(mock_artifact_response):
    """Test successful decryption of an EncryptedID."""
    # Create a minimal SAML EncryptedID structure
    encrypted_id = etree.Element("{urn:oasis:names:tc:SAML:2.0:assertion}EncryptedID")
    encrypted_data = etree.SubElement(
        encrypted_id, "{http://www.w3.org/2001/04/xmlenc#}EncryptedData"
    )

    encrypted_key = etree.SubElement(
        encrypted_id, "{http://www.w3.org/2001/04/xmlenc#}EncryptedKey"
    )
    encrypted_key.set("Recipient", "entity_id_1")

    key_info = etree.SubElement(
        encrypted_key, "{http://www.w3.org/2000/09/xmldsig#}KeyInfo"
    )
    key_name = etree.SubElement(key_info, "{http://www.w3.org/2000/09/xmldsig#}KeyName")
    key_name.text = "keyname1"

    # Call the method
    result = mock_artifact_response.decrypt_id(encrypted_id)

    # Verify the result
    assert result.tag == "NameID"
    assert result.text == "test-id"
    mock_artifact_response._decrypt_enc_key.assert_called_once_with(encrypted_key)
    mock_artifact_response._decrypt_enc_data.assert_called_once_with(
        encrypted_data, b"mock_aes_key"
    )


def test_decrypt_id_no_encrypted_data(mock_artifact_response):
    """Test error when EncryptedData is missing."""
    # Create EncryptedID without EncryptedData
    encrypted_id = etree.Element("{urn:oasis:names:tc:SAML:2.0:assertion}EncryptedID")

    # Call should raise ValueError
    with pytest.raises(ValueError, match="No EncryptedData element found"):
        mock_artifact_response.decrypt_id(encrypted_id)


def test_decrypt_id_wrong_recipient(mock_artifact_response):
    """Test handling of incorrect recipient in strict mode."""
    # Create EncryptedID with wrong recipient
    encrypted_id = etree.Element("{urn:oasis:names:tc:SAML:2.0:assertion}EncryptedID")
    etree.SubElement(encrypted_id, "{http://www.w3.org/2001/04/xmlenc#}EncryptedData")

    encrypted_key = etree.SubElement(
        encrypted_id, "{http://www.w3.org/2001/04/xmlenc#}EncryptedKey"
    )
    encrypted_key.set("Recipient", "wrong-recipient")

    key_info = etree.SubElement(
        encrypted_key, "{http://www.w3.org/2000/09/xmldsig#}KeyInfo"
    )
    key_name = etree.SubElement(key_info, "{http://www.w3.org/2000/09/xmldsig#}KeyName")
    key_name.text = "keyname1"

    # In strict mode with wrong recipient, should fail
    with pytest.raises(
        ValueError,
        match=re.escape(
            "No EncryptedKey found for recipient 'entity_id_1' and keyname 'keyname1'. Available keys: [('keyname1', 'wrong-recipient')]"
        ),
    ):
        mock_artifact_response.decrypt_id(encrypted_id)


def test_decrypt_id_wrong_keyname(mock_artifact_response):
    """Test handling of incorrect keyname."""
    # Create EncryptedID with wrong keyname
    encrypted_id = etree.Element("{urn:oasis:names:tc:SAML:2.0:assertion}EncryptedID")
    etree.SubElement(encrypted_id, "{http://www.w3.org/2001/04/xmlenc#}EncryptedData")

    encrypted_key = etree.SubElement(
        encrypted_id, "{http://www.w3.org/2001/04/xmlenc#}EncryptedKey"
    )
    encrypted_key.set("Recipient", "entity_id_1")

    key_info = etree.SubElement(
        encrypted_key, "{http://www.w3.org/2000/09/xmldsig#}KeyInfo"
    )
    key_name = etree.SubElement(key_info, "{http://www.w3.org/2000/09/xmldsig#}KeyName")
    key_name.text = "wrong-keyname"

    # Should fail due to wrong keyname
    with pytest.raises(
        ValueError,
        match=re.escape(
            "No EncryptedKey found for recipient 'entity_id_1' and keyname 'keyname1'. Available keys: [('wrong-keyname', 'entity_id_1')]"
        ),
    ):
        mock_artifact_response.decrypt_id(encrypted_id)


def test_decrypt_id_clustered_mode_connected_party(mock_artifact_response):
    """Test handling when trying to decrypt data for connected party in clustered mode."""
    # Setup clustered mode with multiple connections
    mock_artifact_response._sp_metadata.clustered = True
    mock_artifact_response._sp_metadata.entity_id = "entity_id_1"
    mock_connection1 = MagicMock()
    mock_connection1.entity_id = "connection_id_1"
    mock_connection2 = MagicMock()
    mock_connection2.entity_id = "connection_id_2"
    mock_artifact_response._sp_metadata.connections = [
        mock_connection1,
        mock_connection2,
    ]

    # Create EncryptedID with connection_id_2 recipient
    encrypted_id = etree.Element("{urn:oasis:names:tc:SAML:2.0:assertion}EncryptedID")
    encrypted_data = etree.SubElement(
        encrypted_id, "{http://www.w3.org/2001/04/xmlenc#}EncryptedData"
    )

    encrypted_key = etree.SubElement(
        encrypted_id, "{http://www.w3.org/2001/04/xmlenc#}EncryptedKey"
    )
    encrypted_key.set(
        "Recipient", "connection_id_2"
    )  # A connection ID, not our entity ID

    key_info = etree.SubElement(
        encrypted_key, "{http://www.w3.org/2000/09/xmldsig#}KeyInfo"
    )
    key_name = etree.SubElement(key_info, "{http://www.w3.org/2000/09/xmldsig#}KeyName")
    key_name.text = "connection_keyname"  # A keyname that would be for the connected party, not in our dv_keynames

    # Should fail because:
    # 1. In strict mode, recipient doesn't match our entity_id
    # 2. The keyname isn't in our dv_keynames list
    with pytest.raises(
        ValueError,
        match=re.escape(
            "No EncryptedKey found for recipient 'entity_id_1' and keyname 'keyname1'. Available keys: [('connection_keyname', 'connection_id_2')]"
        ),
    ):
        mock_artifact_response.decrypt_id(encrypted_id)


def test_decrypt_id_decryption_failure(mock_artifact_response):
    """Test handling of decryption failure."""
    # Create valid EncryptedID structure
    encrypted_id = etree.Element("{urn:oasis:names:tc:SAML:2.0:assertion}EncryptedID")
    encrypted_data = etree.SubElement(
        encrypted_id, "{http://www.w3.org/2001/04/xmlenc#}EncryptedData"
    )

    encrypted_key = etree.SubElement(
        encrypted_id, "{http://www.w3.org/2001/04/xmlenc#}EncryptedKey"
    )
    encrypted_key.set("Recipient", "entity_id_1")

    key_info = etree.SubElement(
        encrypted_key, "{http://www.w3.org/2000/09/xmldsig#}KeyInfo"
    )
    key_name = etree.SubElement(key_info, "{http://www.w3.org/2000/09/xmldsig#}KeyName")
    key_name.text = "keyname1"

    # Make decryption throw an exception
    mock_artifact_response._decrypt_enc_key.side_effect = Exception(
        "Decryption failed"
    )  # pylint: disable=protected-access

    # Should raise the decryption exception
    with pytest.raises(
        Exception,
        match="Decryption failed",
    ):
        mock_artifact_response.decrypt_id(encrypted_id)
