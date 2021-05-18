import os
from pathlib import Path

from pydantic import BaseSettings

BASE_DIR = Path(__file__).resolve().parent.parent
class Settings(BaseSettings):
    app_name: str = "CoronaCheck"
    base_dir: str = str(BASE_DIR)
    saml_path: str = os.path.join(BASE_DIR, 'saml')
    cert_path: str = os.path.join(BASE_DIR, 'saml/certs/sp.crt')
    key_path: str = os.path.join(BASE_DIR, 'saml/certs/sp.key')

settings = Settings()