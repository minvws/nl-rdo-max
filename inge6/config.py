import configparser

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_FILE_NAME = "inge6.conf"
CONFIG_FILE_PATH = str(BASE_DIR) + '/' + CONFIG_FILE_NAME

# pylint: disable=too-many-ancestors, too-few-public-methods
class Settings(configparser.ConfigParser):
    class SettingSection:
        def __init__(self, section: dict):
            self._section: dict = section

        def __getattr__(self, name):
            return self._section[name]

    def __getattr__(self, name):
        if name in self._defaults:
            return self._defaults[name]
        if name in self._sections:
            return self.SettingSection(self._sections[name])
        raise AttributeError("Attribute {} not found".format(name))

settings = Settings()

with open(CONFIG_FILE_PATH) as conf_file:
    settings.read_file(conf_file)
