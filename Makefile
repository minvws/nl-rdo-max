UID = $(shell id -u)
GID = $(shell id -g)
PYTHON_VERSION=3.10

venv: ## Create virtual environment
	poetry install

clean_venv: ## Remove virtual environment
	poetry env remove python

setup-secrets:
	scripts/setup-secrets.sh

setup-saml:
	scripts/setup-saml.sh

setup-config:
	scripts/setup-config.sh

setup-npm:
	scripts/setup-npm.sh

setup-remote: setup-config setup-saml setup-secrets
	docker compose build --build-arg="NEW_UID=${UID}" --build-arg="NEW_GID=${GID}" --build-arg="PYTHON_VERSION=${PYTHON_VERSION}"
setup-local: venv setup-config setup-saml setup-secrets setup-npm

run-remote:
	docker compose up -d

run-local:
	docker compose up -d redis redis-init
	npm run build
	poetry run python -m app.main

stop-remote:
	docker compose down

stop-local:
	docker compose down

check:
	poetry run pylint app
	poetry run black --check app tests

audit:
	poetry run bandit -r app

fix:
	poetry run black app tests

test:
	poetry run pytest --cov --cov-report=term --cov-report=xml

setup-remote-test:
	docker compose -p max-test -f docker-compose.testing.yml build --build-arg="NEW_UID=${UID}" --build-arg="NEW_GID=${GID}" --build-arg="PYTHON_VERSION=${PYTHON_VERSION}"

test-remote:
	docker compose -p max-test -f docker-compose.testing.yml up

type-check:
	poetry run mypy

check-all: fix check type-check test audit
