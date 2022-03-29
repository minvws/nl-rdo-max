"""Settings module for :mod:`inge6`."""
import os

from inge6.config import get_settings


cfg = get_settings()

DEBUG = (os.getenv("DEBUG") == "1") or (cfg.debug == "True")

DEPLOYMENT_ENV = os.getenv("DEPLOYMENT_ENV") or "production"

HOST = cfg.host

LOG_LEVEL = str.upper(os.getenv("LOG_LEVEL") or cfg.loglevel or "WARNING")

PORT = int(cfg.port)

SSL_DIR = cfg.ssl.base_dir

SSL_CERTFILE = os.path.join(SSL_DIR, cfg.ssl.cert_file)

SSL_KEYFILE = os.path.join(SSL_DIR, cfg.ssl.key_file)

TEST_STAGE = os.getenv("TEST_STAGE")

USE_SSL = str.lower(getattr(cfg, "use_ssl", "false")) == "true"
