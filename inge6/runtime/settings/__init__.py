"""Settings module for :mod:`inge6`."""
import os

from inge6.config import get_settings


cfg = get_settings()

DEPLOYMENT_ENV = os.getenv('DEPLOYMENT_ENV') or 'production'

TEST_STAGE = os.getenv('TEST_STAGE')
