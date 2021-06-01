import os
import configparser

from pathlib import Path

from pydantic import BaseSettings

BASE_DIR = Path(__file__).resolve().parent.parent

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
# def init_settings(filename: str ="inge6.conf"):
filename = "inge6.conf"
path = str(BASE_DIR) + '/' + filename
with open(path) as conf_file:
    settings.read_file(conf_file)
