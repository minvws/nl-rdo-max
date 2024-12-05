from pathlib import Path

import inject

from app.vad.utils import root_path


class KeyRepository:
    @inject.autoparams()
    def __init__(self, path_to_jwe_key: str):
        self.path_to_jwe_key = path_to_jwe_key

    def get_jwe_encryption_key(self) -> bytes:
        key_path = root_path(self.path_to_jwe_key)
        with Path(key_path).open("rb") as key_file:
            return key_file.read()
