import configparser
from typing import Any
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_FILE_NAME = "inge6.conf"
CONFIG_FILE_PATH = str(BASE_DIR) + '/' + CONFIG_FILE_NAME

# pylint: disable=too-many-ancestors, too-few-public-methods
class Settings(configparser.ConfigParser):
    class SettingSection:
        def __init__(self, parent: str, section: dict):
            self._section: dict = section
            self._parent: str = parent

        def __getattr__(self, name):
            if name in self._section:
                value = self._section[name]
                if str(value).lower() == "true":
                    return True

                if str(value).lower() == "false":
                    return False

                return value
            raise AttributeError("Setting {}.{} not found and not handled gracefully".format(self._parent, name))

        def __setattr__(self, name: str, value: Any) -> None:
            if name != '_section':
                self._section[name] = value
            else:
                super().__setattr__(name, value)

    def __getattr__(self, name):
        if name in self._defaults:
            return self._defaults[name]
        if name in self._sections:
            return self.SettingSection(name, self._sections[name])
        raise AttributeError("Setting {} not found and not handled gracefully".format(name))

settings = Settings()

with open(CONFIG_FILE_PATH, 'r', encoding='utf-8') as conf_file:
    settings.read_file(conf_file)
