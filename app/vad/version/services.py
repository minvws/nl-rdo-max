import json

from app.vad.utils import root_path
from .models import VersionInfo


def read_version_info() -> VersionInfo:
    with open(root_path("version.json"), "r") as file:
        return VersionInfo(**json.load(file))
