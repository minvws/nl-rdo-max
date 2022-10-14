env = env PATH="${bin}:$$PATH"
create_key_pair =

complete: venv secrets/ssl/private/apache-selfsigned.key secrets/oidc/private/selfsigned.key

venv: .venv/touchfile ## Create virtual environment
.venv/touchfile:
	test -d .venv || python3 -m venv .venv
	. .venv/bin/activate; pip install -U pip
	. .venv/bin/activate; pip install pip-tools
	. .venv/bin/activate && ${env} pip-compile --extra dev
	. .venv/bin/activate && ${env} pip-sync
	. .venv/bin/activate && ${env} pip install -e .
	touch .venv/touchfile

clean_venv: ## Remove virtual environment
	@echo "Cleaning venv"
	@rm -rf .venv

run:
	docker-compose stop && docker-compose up -d
	source .venv/bin/activate && python3 -m app.main

pip-sync: ## synchronizes the .venv with the state of requirements.txt
	. .venv/bin/activate && ${env} pip-compile --extra dev
	. .venv/bin/activate && ${env} pip-sync
	. .venv/bin/activate && ${env} pip install -e .

secrets/ssl:
	mkdir -p -m 750 secrets/ssl/certs
	mkdir -p -m 750 secrets/ssl/private

secrets/ssl/private/apache-selfsigned.key: secrets/ssl
	openssl req -newkey rsa:2048 -nodes -keyout secrets/ssl/private/apache-selfsigned.key -x509 -days 365 -out secrets/ssl/certs/apache-selfsigned.crt  -subj '/CN=max-ssl/C=NL'

secrets/oidc:
	mkdir -p -m 750 secrets/oidc/certs
	mkdir -p -m 750 secrets/oidc/private

secrets/oidc/private/selfsigned.key: secrets/oidc
	openssl req -newkey rsa:2048 -nodes -keyout secrets/oidc/private/selfsigned.key -x509 -days 365 -out secrets/oidc/certs/selfsigned.crt  -subj '/CN=max-oidc/C=NL'

setup-secrets:
	./setup-secrets.sh

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

saml-files: saml/tvs/certs/sp.crt saml/digid/certs/sp.crt saml/identity_providers metadata

metadata:
	mkdir -p saml/digid/metadata
	mkdir -p saml/tvs/metadata
	curl "https://was-preprod1.digid.nl/saml/idp/metadata" --output saml/digid/metadata/idp_metadata.xml
	curl "https://pp2.toegang.overheid.nl/kvs/rd/metadata" --output saml/tvs/metadata/idp_metadata.xml

config: max.conf clients.json saml-settings
saml-settings: saml-tvs-settings saml-digid-settings
saml-tvs-settings: saml-tvs-advanced-settings saml-tvs-settings-json
saml-digid-settings: saml-digid-advanced-settings saml-digid-settings-json
saml-digid-advanced-settings:
	cp saml/digid/advanced_settings.json.example saml/digid/advanced_settings.json

saml-digid-settings-json:
	cp saml/digid/settings.json.example saml/digid/settings.json

saml-tvs-advanced-settings:
	cp saml/tvs/advanced_settings.json.example saml/tvs/advanced_settings.json

saml-tvs-settings-json:
	cp saml/tvs/settings.json.example saml/tvs/settings.json

max.conf:
	cp max.conf.example max.conf

clients.json:
	cp clients.json.example clients.json
