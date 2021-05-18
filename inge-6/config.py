import os
from pathlib import Path

from pydantic import BaseSettings

BASE_DIR = Path(__file__).resolve().parent.parent
class Settings(BaseSettings):
    app_name: str = "CoronaCheck"
    SUBJECT_ID_HASH_SALT: str = "FDAfagse32432532#@fFdsgsdpkflds"
    base_dir: str = str(BASE_DIR)
    saml_path: str = os.path.join(BASE_DIR, 'saml')
    cert_path: str = os.path.join(BASE_DIR, 'saml/certs/sp.crt')
    key_path: str = os.path.join(BASE_DIR, 'saml/certs/sp.key')
    redis_host: str = "localhost"
    redis_port: str = "6379"

settings = Settings()