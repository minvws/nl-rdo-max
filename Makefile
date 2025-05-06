UID = $(shell id -u)
GID = $(shell id -g)
PYTHON_VERSION=3.10

env = env PATH="${bin}:$$PATH"
create_key_pair =

venv: .venv/touchfile ## Create virtual environment
.venv/touchfile: ## Includes workaround for https://github.com/xmlsec/python-xmlsec/issues/320
	test -d .venv || python3 -m venv .venv
	. .venv/bin/activate; pip install -U pip
	. .venv/bin/activate; pip install pip-tools
	. .venv/bin/activate && ${env} pip install -r requirements.txt
	. .venv/bin/activate && ${env} pip install --force-reinstall --no-binary=xmlsec xmlsec==1.3.15
	. .venv/bin/activate && ${env} pip install --force-reinstall --no-binary=lxml lxml==5.4.0


	touch .venv/touchfile

clean_venv: ## Remove virtual environment
	@echo "Cleaning venv"
	@rm -rf .venv

pip-sync: ## synchronizes the .venv with the state of requirements.txt
	. .venv/bin/activate && ${env} pip-compile --extra dev
	. .venv/bin/activate && ${env} pip-sync
	. .venv/bin/activate && ${env} pip install -e .

setup-secrets:
	scripts/./setup-secrets.sh

setup-saml:
	scripts/./setup-saml.sh

setup-config:
	scripts/./setup-config.sh

setup-npm:
	scripts/./setup-npm.sh	

setup-remote: setup-config setup-saml setup-secrets
	docker compose build --build-arg="UID=${UID}" --build-arg="GID=${GID}" --build-arg="PYTHON_VERSION=${PYTHON_VERSION}"

setup-local: venv setup-config setup-saml setup-secrets setup-npm

run-remote:
	docker compose up -d

run-local:
	docker compose up -d redis redis-init
	npm run build
	. .venv/bin/activate && ${env} python -m app.main

check:
	. .venv/bin/activate && ${env} pylint app
	. .venv/bin/activate && ${env} black --check app tests

audit:
	. .venv/bin/activate && ${env} bandit app

fix:
	. .venv/bin/activate && $(env) black app tests

test: venv setup-local
	. .venv/bin/activate && ${env} pytest tests

setup-remote-test: 
	docker compose -p max-test -f docker-compose.testing.yml build --build-arg="UID=${UID}" --build-arg="GID=${GID}" --build-arg="PYTHON_VERSION=${PYTHON_VERSION}"

test-remote: 
	docker compose -p max-test -f docker-compose.testing.yml up

type-check:
	. .venv/bin/activate && ${env} MYPYPATH=stubs/ mypy --show-error-codes app

coverage:
	. .venv/bin/activate && ${env} coverage run -m pytest tests && coverage report && coverage html && coverage xml

check-all: fix check type-check test audit
