import os
from pathlib import Path

from pydantic import BaseSettings

BASE_DIR = Path(__file__).resolve().parent.parent

class Settings(BaseSettings):
    app_name: str = "CoronaCheck"
    saml_path: str = os.path.join(BASE_DIR, 'saml')

settings = Settings()