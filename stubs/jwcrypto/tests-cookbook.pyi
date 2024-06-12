import unittest
from _typeshed import Incomplete
from jwcrypto import jwe as jwe, jwk as jwk, jws as jws
from jwcrypto.common import base64url_decode as base64url_decode, base64url_encode as base64url_encode, json_decode as json_decode, json_encode as json_encode

EC_Public_Key_3_1: Incomplete
EC_Private_Key_3_2: Incomplete
RSA_Public_Key_3_3: Incomplete
RSA_Private_Key_3_4: Incomplete
Symmetric_Key_MAC_3_5: Incomplete
Symmetric_Key_Enc_3_6: Incomplete
Payload_plaintext_b64_4: Incomplete
JWS_Protected_Header_4_1_2: Incomplete
JWS_Signature_4_1_2: Incomplete
JWS_compact_4_1_3: Incomplete
JWS_general_4_1_3: Incomplete
JWS_flattened_4_1_3: Incomplete
JWS_Protected_Header_4_2_2: Incomplete
JWS_Signature_4_2_2: Incomplete
JWS_compact_4_2_3: Incomplete
JWS_general_4_2_3: Incomplete
JWS_flattened_4_2_3: Incomplete
JWS_Protected_Header_4_3_2: Incomplete
JWS_Signature_4_3_2: Incomplete
JWS_compact_4_3_3: Incomplete
JWS_general_4_3_3: Incomplete
JWS_flattened_4_3_3: Incomplete
JWS_Protected_Header_4_4_2: Incomplete
JWS_Signature_4_4_2: str
JWS_compact_4_4_3: Incomplete
JWS_general_4_4_3: Incomplete
JWS_flattened_4_4_3: Incomplete
JWS_Protected_Header_4_6_2: str
JWS_Unprotected_Header_4_6_2: Incomplete
JWS_Signature_4_6_2: str
JWS_general_4_6_3: Incomplete
JWS_flattened_4_6_3: Incomplete
JWS_Unprotected_Header_4_7_2: Incomplete
JWS_Signature_4_7_2: str
JWS_general_4_7_3: Incomplete
JWS_flattened_4_7_3: Incomplete
JWS_Protected_Header_4_8_2: str
JWS_Unprotected_Header_4_8_2: Incomplete
JWS_Signature_4_8_2: Incomplete
JWS_Unprotected_Header_4_8_3: Incomplete
JWS_Signature_4_8_3: Incomplete
JWS_Protected_Header_4_8_4: Incomplete
JWS_Signature_4_8_4: str
JWS_general_4_8_5: Incomplete

class Cookbook08JWSTests(unittest.TestCase):
    def test_4_1_signing(self) -> None: ...
    def test_4_2_signing(self) -> None: ...
    def test_4_3_signing(self) -> None: ...
    def test_4_4_signing(self) -> None: ...
    def test_4_6_signing(self) -> None: ...
    def test_4_7_signing(self) -> None: ...
    def test_4_8_signing(self) -> None: ...

Payload_plaintext_5: Incomplete
RSA_key_5_1_1: Incomplete
JWE_IV_5_1_2: str
JWE_Encrypted_Key_5_1_3: Incomplete
JWE_Protected_Header_5_1_4: Incomplete
JWE_Ciphertext_5_1_4: Incomplete
JWE_Authentication_Tag_5_1_4: str
JWE_compact_5_1_5: Incomplete
JWE_general_5_1_5: Incomplete
JWE_flattened_5_1_5: Incomplete
RSA_key_5_2_1: Incomplete
JWE_IV_5_2_2: str
JWE_Encrypted_Key_5_2_3: Incomplete
JWE_Protected_Header_5_2_4: Incomplete
JWE_Ciphertext_5_2_4: Incomplete
JWE_Authentication_Tag_5_2_4: str
JWE_compact_5_2_5: Incomplete
JWE_general_5_2_5: Incomplete
JWE_flattened_5_2_5: Incomplete
Payload_plaintext_5_3_1: Incomplete
Password_5_3_1: bytes
JWE_IV_5_3_2: str
JWE_Encrypted_Key_5_3_3: str
JWE_Protected_Header_no_p2x: Incomplete
JWE_Protected_Header_5_3_4: Incomplete
JWE_Ciphertext_5_3_4: Incomplete
JWE_Authentication_Tag_5_3_4: str
JWE_compact_5_3_5: Incomplete
JWE_general_5_3_5: Incomplete
JWE_flattened_5_3_5: Incomplete
EC_key_5_4_1: Incomplete
JWE_IV_5_4_2: str
JWE_Encrypted_Key_5_4_3: str
JWE_Protected_Header_no_epk_5_4_4: Incomplete
JWE_Protected_Header_5_4_4: Incomplete
JWE_Ciphertext_5_4_4: Incomplete
JWE_Authentication_Tag_5_4_4: str
JWE_compact_5_4_5: Incomplete
JWE_general_5_4_5: Incomplete
JWE_flattened_5_4_5: Incomplete
EC_key_5_5_1: Incomplete
JWE_IV_5_5_2: str
JWE_Protected_Header_no_epk_5_5_4: Incomplete
JWE_Protected_Header_5_5_4: Incomplete
JWE_Ciphertext_5_5_4: Incomplete
JWE_Authentication_Tag_5_5_4: str
JWE_compact_5_5_5: Incomplete
JWE_general_5_5_5: Incomplete
AES_key_5_6_1: Incomplete
JWE_IV_5_6_2: str
JWE_Protected_Header_5_6_3: Incomplete
JWE_Ciphertext_5_6_3: Incomplete
JWE_Authentication_Tag_5_6_3: str
JWE_compact_5_6_4: Incomplete
JWE_general_5_6_4: Incomplete
AES_key_5_7_1: Incomplete
JWE_IV_5_7_2: str
JWE_Encrypted_Key_5_7_3: str
JWE_Protected_Header_no_ivtag: Incomplete
JWE_Protected_Header_5_7_4: Incomplete
JWE_Ciphertext_5_7_4: Incomplete
JWE_Authentication_Tag_5_7_4: str
JWE_compact_5_7_5: Incomplete
JWE_general_5_7_5: Incomplete
JWE_flattened_5_7_5: Incomplete
AES_key_5_8_1: Incomplete
JWE_IV_5_8_2: str
JWE_Encrypted_Key_5_8_3: str
JWE_Protected_Header_5_8_4: Incomplete
JWE_Ciphertext_5_8_4: Incomplete
JWE_Authentication_Tag_5_8_4: str
JWE_compact_5_8_5: Incomplete
JWE_general_5_8_5: Incomplete
JWE_flattened_5_8_5: Incomplete
JWE_IV_5_9_2: str
JWE_Encrypted_Key_5_9_3: str
JWE_Protected_Header_5_9_4: Incomplete
JWE_Ciphertext_5_9_4: Incomplete
JWE_Authentication_Tag_5_9_4: str
JWE_compact_5_9_5: Incomplete
JWE_general_5_9_5: Incomplete
JWE_flattened_5_9_5: Incomplete
AAD_5_10_1: Incomplete
JWE_IV_5_10_2: str
JWE_Encrypted_Key_5_10_3: str
JWE_Protected_Header_5_10_4: Incomplete
JWE_Ciphertext_5_10_4: Incomplete
JWE_Authentication_Tag_5_10_4: str
JWE_general_5_10_5: Incomplete
JWE_flattened_5_10_5: Incomplete
JWE_IV_5_11_2: str
JWE_Encrypted_Key_5_11_3: str
JWE_Protected_Header_5_11_4: str
JWE_Ciphertext_5_11_4: Incomplete
JWE_Authentication_Tag_5_11_4: str
JWE_Unprotected_Header_5_11_5: Incomplete
JWE_general_5_11_5: Incomplete
JWE_flattened_5_11_5: Incomplete
JWE_IV_5_12_2: str
JWE_Encrypted_Key_5_12_3: str
JWE_Ciphertext_5_12_4: Incomplete
JWE_Authentication_Tag_5_12_4: str
JWE_Unprotected_Header_5_12_5: Incomplete
JWE_general_5_12_5: Incomplete
JWE_flattened_5_12_5: Incomplete

class Cookbook08JWETests(unittest.TestCase):
    def test_5_1_encryption(self) -> None: ...
    def test_5_2_encryption(self) -> None: ...
    def test_5_3_encryption(self) -> None: ...
    def test_5_4_encryption(self) -> None: ...
    def test_5_5_encryption(self) -> None: ...
    def test_5_6_encryption(self) -> None: ...
    def test_5_7_encryption(self) -> None: ...
    def test_5_8_encryption(self) -> None: ...
    def test_5_9_encryption(self) -> None: ...
    def test_5_10_encryption(self) -> None: ...
    def test_5_11_encryption(self) -> None: ...
    def test_5_12_encryption(self) -> None: ...
