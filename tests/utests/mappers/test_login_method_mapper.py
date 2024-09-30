import unittest

from app.mappers.login_method_mapper import (
    map_login_methods_json_to_list_of_objects,
    get_optional_string_from_dict,
    get_string_from_dict,
    get_optional_boolean_from_dict,
)
from app.models.login_method import LoginMethod
from app.models.login_method_type import LoginMethodType


class TestLoginMethodMapper(unittest.TestCase):

    def test_map_login_methods_dict_to_list(self):
        raw_login_methods = [
            {
                "name": "digid_mock",
                "logo": "static/img/digid-logo.svg",
                "text": "Inloggen met DigiD mock",
                "type": "specific",
                "hidden": False,
            },
            {
                "name": "uzipas",
                "logo": "static/img/uzipas.svg",
                "text": "Inloggen met UZI-pas",
                "type": "specific",
                "hidden": True,
            },
        ]

        expected_login_methods = [
            LoginMethod(
                name="digid_mock",
                logo="static/img/digid-logo.svg",
                text="Inloggen met DigiD mock",
                type=LoginMethodType.SPECIFIC,
                hidden=False,
            ),
            LoginMethod(
                name="uzipas",
                logo="static/img/uzipas.svg",
                text="Inloggen met UZI-pas",
                type=LoginMethodType.SPECIFIC,
                hidden=True,
            ),
        ]

        result = map_login_methods_json_to_list_of_objects(raw_login_methods)
        assert result == expected_login_methods

    def test_get_optional_string_from_dict(self):
        raw_login_method = {"key1": "value1", "key2": True}

        assert get_optional_string_from_dict(raw_login_method, "key1") == "value1"
        assert get_optional_string_from_dict(raw_login_method, "key2") is None
        assert get_optional_string_from_dict(raw_login_method, "key3") is None

    def test_get_string_from_dict(self):
        raw_login_method = {"key1": "value1", "key2": True}

        assert get_string_from_dict(raw_login_method, "key1") == "value1"
        with self.assertRaises(ValueError):
            get_string_from_dict(raw_login_method, "key2")
        with self.assertRaises(ValueError):
            get_string_from_dict(raw_login_method, "key3")

    def test_get_optional_boolean_from_dict(self):
        raw_login_method = {"key1": "value1", "key2": True, "key3": False}

        assert get_optional_boolean_from_dict(raw_login_method, "key1") is False
        assert get_optional_boolean_from_dict(raw_login_method, "key2") is True
        assert get_optional_boolean_from_dict(raw_login_method, "key3") is False
        assert get_optional_boolean_from_dict(raw_login_method, "key4") is False
        assert get_optional_boolean_from_dict(raw_login_method, "key4", True) is True
