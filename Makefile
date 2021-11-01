env = env PATH="${bin}:$$PATH"

venv: .venv/touchfile ## Create virtual environment
.venv/touchfile:
	test -d .venv || python3 -m venv .venv
	. .venv/bin/activate; pip install -U pip
	. .venv/bin/activate; pip install pip-tools
	. .venv/bin/activate && ${env} python3 -m piptools compile --output-file requirements-dev.txt requirements.in requirements-dev.in
	. .venv/bin/activate && ${env} python3 -m piptools sync requirements.txt requirements-dev.txt
	. .venv/bin/activate && ${env} pip install -e .
	touch .venv/touchfile

clean_venv: ## Remove virtual environment
	@echo "Cleaning venv"
	@rm -rf .venv

clients.json: clients.json.example
	cp clients.json.example clients.json

inge6.conf: inge6.conf.example
	cp inge6.conf.example inge6.conf

saml/tvs/settings.json: saml/settings.json.example
	cp saml/settings.json.example saml/tvs/settings.json

saml/digid/settings.json: saml/settings.json.example
	cp saml/settings.json.example saml/digid/settings.json

secrets/private_unencrypted.pem:
	openssl genrsa -out secrets/private_unencrypted.pem 2048
secrets/public.pem: secrets/private_unencrypted.pem
	openssl rsa -in secrets/private_unencrypted.pem -pubout -out secrets/public.pem

secrets/ssl:
	mkdir -p secrets/ssl/certs
	mkdir -p secrets/ssl/private

secrets/ssl/private/apache-selfsigned.key: secrets/ssl
	openssl req -newkey rsa:2048 -nodes -keyout secrets/ssl/private/apache-selfsigned.key -x509 -days 365 -out secrets/ssl/certs/apache-selfsigned.crt  -subj '/CN=inge6/C=NL'

secrets-redis-certs:
	mkdir -p secrets/redis/certs
	mkdir -p secrets/redis/private

	openssl genrsa -out secrets/redis/private/cacert.key 4096
	openssl req -x509 -new -nodes -key secrets/redis/private/cacert.key -sha256 -days 1024 -out secrets/redis/certs/cacert.crt -subj "/CN=US/CN=inge6.redisserver.ca"
	openssl genrsa -out secrets/redis/private/redis_key.key 2048
	openssl req -new -sha256 -key secrets/redis/private/redis_key.key -subj "/C=US/CN=inge6.redisserver" -out secrets/redis/certs/redis_key.csr
	openssl x509 -req -in secrets/redis/certs/redis_key.csr -CA secrets/redis/certs/cacert.crt -CAkey secrets/redis/private/cacert.key -CAcreateserial -out secrets/redis/certs/cert.crt -days 500 -sha256

saml/tvs/certs/sp.key:
	openssl genrsa -out saml/tvs/certs/sp.key 2048
saml/tvs/certs/sp.crt: saml/tvs/certs/sp.key
	openssl req -new -x509 -key saml/tvs/certs/sp.key -out saml/tvs/certs/sp.crt -days 360 -subj "/C=US/ST=SCA/L=SCA/O=Oracle/OU=Java/CN=test cert"

saml/digid/certs/sp.key:
	openssl genrsa -out saml/digid/certs/sp.key 2048
saml/digid/certs/sp.crt: saml/digid/certs/sp.key
	openssl req -new -x509 -key saml/digid/certs/sp.key -out saml/digid/certs/sp.crt -days 360 -subj "/C=US/ST=SCA/L=SCA/O=Oracle/OU=Java/CN=test cert"

saml/identity_providers:
	cp saml/identity_providers.json.example saml/identity_providers.json

saml-files: saml/tvs/certs/sp.crt saml/digid/certs/sp.crt saml/identity_providers saml/tvs/settings.json

secret-files: secrets/public.pem secrets/ssl/private/apache-selfsigned.key

setup: inge6.conf clients.json saml secrets/ssl secret-files saml-files secrets-redis-certs

fresh: clean_venv venv

pip-compile: ## synchronizes the .venv with the state of requirements.txt
	. .venv/bin/activate && ${env} python3 -m piptools compile requirements.in
	. .venv/bin/activate && ${env} python3 -m piptools compile --output-file requirements-dev.txt requirements.in requirements-dev.in

pip-sync: ## synchronizes the .venv with the state of requirements.txt
	. .venv/bin/activate && ${env} python3 -m piptools sync requirements.txt
	. .venv/bin/activate && ${env} pip install -e .

pip-sync-dev: ## synchronizes the .venv with the state of requirements.txt
	. .venv/bin/activate && ${env} python3 -m piptools sync requirements-dev.txt
	. .venv/bin/activate && ${env} pip install -e .

lint:
	. .venv/bin/activate && ${env} pylint inge6 tests
	. .venv/bin/activate && ${env} black --check inge6 tests

audit:
	. .venv/bin/activate && ${env} bandit inge6

fix:
	. .venv/bin/activate && $(env) black inge6 tests

test:
	. .venv/bin/activate && ${env} pytest tests

type-check:
	. .venv/bin/activate && ${env} MYPYPATH=stubs/ mypy --show-error-codes inge6

check-all: lint type-check test audit
