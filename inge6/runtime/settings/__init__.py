"""Settings module for :mod:`inge6`."""
import json
import os

from jwkest.jwk import rsa_load
from jwkest.jwk import RSAKey

from inge6.config import get_settings


cfg = get_settings()

DEBUG = (os.getenv("DEBUG") == "1") or (cfg.debug == "True")

DEPLOYMENT_ENV = os.getenv("DEPLOYMENT_ENV") or "production"

HOST = cfg.host

ID_TOKEN_TTL = int(cfg.oidc.id_token_lifetime)

JWKS_ENDPOINT = cfg.jwks_endpoint

LOG_LEVEL = str.upper(os.getenv("LOG_LEVEL") or cfg.loglevel or "WARNING")

OAUTH2_AUTHORIZATION_ENDPOINT = cfg.authorize_endpoint

OAUTH2_TOKEN_ENDPOINT = cfg.accesstoken_endpoint

with open(cfg.oidc.clients_file, "r", encoding="utf-8") as f:
    OIDC_CLIENTS = json.load(f)

OIDC_AUDIENCE = list(dict.keys(OIDC_CLIENTS))

OIDC_ISSUER = cfg.issuer

with open(cfg.oidc.rsa_public_key, "r", encoding="utf-8") as f:
    OIDC_PUBLIC_KEY = f.read()

PORT = int(cfg.port)

REDIS_CODE_NS = cfg.redis.code_namespace

REDIS_REFRESH_TOKEN_NS = cfg.redis.refresh_token_namespace

REDIS_SUBJECT_ID_NS = cfg.redis.sub_id_namespace

REDIS_TOKEN_NS = cfg.redis.token_namespace

SIGNING_KEY = RSAKey(key=rsa_load(cfg.oidc.rsa_private_key), alg="RS256")

SSL_DIR = cfg.ssl.base_dir

SSL_CERTFILE = os.path.join(SSL_DIR, cfg.ssl.cert_file)

SSL_KEYFILE = os.path.join(SSL_DIR, cfg.ssl.key_file)

SUBJECT_ID_HASH_SALT = cfg.oidc.subject_id_hash_salt

TEST_STAGE = os.getenv("TEST_STAGE")

TRANSIENT_OBJECT_TTL = int(cfg.redis.object_ttl)

USE_SSL = str.lower(getattr(cfg, "use_ssl", "false")) == "true"
