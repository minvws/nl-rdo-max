import configparser
import os
from typing import Any, Dict

from .schemas import Config


class ConfigParser:
    DEFAULT_SECTION = "default"

    def __init__(
        self,
        config_parser: configparser.ConfigParser,
        config_path: str,
    ) -> None:
        self.config_parser = config_parser
        self.config_path = config_path

    def parse(self) -> Config:
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(
                f"Configuration file '{self.config_path}' not found."
            )

        self.config_parser.read(self.config_path)

        conf_values: Dict[str, Any] = {}

        for section in self.config_parser.sections():
            section_values = dict(self.config_parser[section])
            conf_values.update(
                {section: section_values}
                if section != self.DEFAULT_SECTION
                else section_values
            )

        return Config(**conf_values)
