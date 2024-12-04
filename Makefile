env = env PATH="${bin}:$$PATH"
create_key_pair =

venv: .venv/touchfile ## Create virtual environment
.venv/touchfile: ## Includes workaround for https://github.com/xmlsec/python-xmlsec/issues/320
	test -d .venv || python3 -m venv .venv
	. .venv/bin/activate; pip install -U pip
	. .venv/bin/activate; pip install pip-tools
	. .venv/bin/activate && ${env} pip-compile --extra dev
	. .venv/bin/activate && ${env} pip-sync
	. .venv/bin/activate && ${env} pip install -e .
	. .venv/bin/activate && ${env} pip install --no-binary lxml==4.9.3 lxml==4.9.3 --force-reinstall
	. .venv/bin/activate && ${env} pip install --no-binary xmlsec==1.3.14 xmlsec==1.3.14 --force-reinstall

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

docker-build:
	NODE_VERSION=$$(cat ./.nvmrc) && docker compose build --build-arg NODE_VERSION=$$NODE_VERSION

setup-docker: setup-config setup-saml setup-secrets docker-build

setup-venv: venv setup-config setup-saml setup-secrets setup-npm

run-docker:
	docker compose up

run-venv:
	docker compose up -d
	npm run build
	. .venv/bin/activate && ${env} python -m app.main

check:
	. .venv/bin/activate && ${env} pylint app
	. .venv/bin/activate && ${env} black --check app tests

audit:
	. .venv/bin/activate && ${env} bandit app

fix:
	. .venv/bin/activate && $(env) black app tests

test: venv setup
	. .venv/bin/activate && ${env} pytest tests

type-check:
	. .venv/bin/activate && ${env} MYPYPATH=stubs/ mypy --show-error-codes app

coverage:
	. .venv/bin/activate && ${env} coverage run -m pytest tests && coverage report && coverage html && coverage xml

check-all: fix check type-check test audit
