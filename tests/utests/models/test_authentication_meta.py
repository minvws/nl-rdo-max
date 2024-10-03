import unittest
from unittest.mock import Mock
from starlette.requests import Request

from app.exceptions.max_exceptions import ServerErrorException
from app.models.authentication_meta import AuthenticationMeta
from app.models.login_method import LoginMethod
from app.models.login_method_type import LoginMethodType


class TestAuthenticationMeta(unittest.TestCase):
    def setUp(self):
        self.mock_request = Mock(spec=Request)
        self.mock_request.client.host = "192.168.1.1"
        self.mock_request.headers = {"User-Agent": "test-agent"}

        self.authentication_method = LoginMethod(
            name="digid",
            logo="static/img/digid-logo.svg",
            text="Inloggen met DigiD",
            type=LoginMethodType.SPECIFIC,
        )

    def test_create_authentication_meta_success(self):
        auth_meta = AuthenticationMeta.create_authentication_meta(
            self.mock_request, self.authentication_method
        )

        self.assertEqual(auth_meta.ip, "192.168.1.1")
        self.assertEqual(auth_meta.headers, {"User-Agent": "test-agent"})
        self.assertEqual(auth_meta.authentication_method_name, "digid")

    def test_create_authentication_meta_missing_client(self):
        self.mock_request.client = None

        with self.assertRaises(ServerErrorException):
            AuthenticationMeta.create_authentication_meta(
                self.mock_request, self.authentication_method
            )

    def test_authentication_meta_json_dump(self):
        auth_meta = AuthenticationMeta.create_authentication_meta(
            self.mock_request, self.authentication_method
        )

        expected_json = (
            '{"ip":"192.168.1.1","headers":{"User-Agent":"test-agent"},'
            '"authentication_method_name":"digid"}'
        )

        self.assertEqual(auth_meta.json(), expected_json)
