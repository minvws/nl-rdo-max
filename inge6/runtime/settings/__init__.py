"""Settings module for :mod:`inge6`."""
import os


DEPLOYMENT_ENV = os.getenv('DEPLOYMENT_ENV') or 'production'

TEST_STAGE = os.getenv('TEST_STAGE')
