# Setup

As Inge6 is a OIDC <-> SAML bridge, one has to have files for both. Each file is described below. Further, one needs to create an `inge6.conf` to define all settings. An example is found in inge6.conf.example with the corresponding explanations

## OIDC
For the Open ID Connect protocol we need a file containing the allowed clients. These clients are defined in the `clients_file` setting in the settings file. An example of such a file is found under `clients.json.example`. Finally, one needs to setup a public-private keypair for signing and verification of JWT tokens. Both locations configurable in the settings file.

In short, setup these files:
- `clients_file`, location configurable in the settings.
- `rsa_private_key`, for JWT token signing. Location configurable in the settings
- `rsa_public_key`, for JWT token verifcation. Location configurable in the settings

## SAML
SAML handles the communication between Inge6 and the IdP, short for Identity Provider, which is either TVS or DigiD. To make this work we need to setup the SAML directory.

In the configured `identity_provider_settings` file, please make sure that these files are available for each IdP, and reference to the correct IdP files:
- `cert_path`, the certificate used for verifying our signed message. Passed along in requests
- `key_path`, the key used for signing SAML requests
- `settings_path`, a file containing the SAML settings for creating our metadata and requests, and parsing the IdP metadata. An example is provided in saml/settings-dist.json, this file also includes an explanation of the options.
- `idp_metadata_path`, the location of the metadata of the IdP

**note: each idp configured idp is expected to have a subdomain to the configured issuer (with TLS support).**

Template files (these are included in the repository):
- `sp_template`, saml/templates/xml/sp_metadata.xml
- `authn_request_template`, saml/templates/xml/authn_request.xml
- `artifactresolve_request_template`, saml/templates/xml/artifactresolve_request.xml
- `authn_request_html_template`, saml/templates/html/authn_request.html

## Redis
Redis is the store of this service. It is used to temporarily store data acquired during the BSN retrieval process. A redis-server should be setup, and the configuration should be copied in the settings file under the `redis` header.

## SSL (local development)
An SSL connection is usually required, also in an development environment. To set this up, please define where to find the certificates and keys in the settings file under the `ssl` header.

# Setup Instructions

There are two ways to set up this project:

- **Local Installation**: Install tools like Python and npm directly on your local machine. This requires manual setup of dependencies.
- **Remote Docker Container**: Use a preconfigured Docker container for development.

## 1. Local Installation

### Dependencies

Install required system packages:

```bash
sudo apt-get update && sudo apt-get install libxmlsec1-dev
```

### Install npm

Install npm if not already installated ([npm documentation](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm))
As GitHub is used as an npm repository, set your GitHub token in your `.npmrc` file before running npm install.

### Steps:
1. Generate a GitHub token with the `read:packages` scope ([Generate Token](https://docs.github.com/en/packages/using-github-packages-with-your-projects-ecosystem/configuring-npm-for-use-with-github-packages)).
2. Add the token to your `.npmrc` file:
```bash
//npm.pkg.github.com/:_authToken=YOUR_TOKEN
```
3. Set up the project: `make setup-local`
4. Run the service: `make run-local`

## 2. Remote Docker Container

### Steps:
1. Generate a GitHub token with the `read:packages` scope ([Generate Token](https://docs.github.com/en/packages/using-github-packages-with-your-projects-ecosystem/configuring-npm-for-use-with-github-packages)).
2. Add the token to your `.npmrc` file:
```bash
//npm.pkg.github.com/:_authToken=YOUR_TOKEN
```
3. Build the project: `make setup-remote`
4. Run the service: `make run-remote`


# Contributions
When contributing to inge6 a few Make commands should be considered to make sure linting, type-checking (MyPy) and tests are still valid:
- `make lint`, check linting using pylint.
- `make check-type`, check that typing is done correctly. Also, see 'MyPy: stubs'.
- `make test`, run the tests

or 
- `make check-all`, to check all the above

## MyPy: stubs
To make use of our custom stubs when running mypy make sure you have correctly exported the env variable:
```bash
$ export MYPYPATH=~/work/myproject/stubs
```
