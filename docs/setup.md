# Setup

As Inge6 is a OIDC <-> SAML bridge, one has to have files for both. Each file is described below. Further, one needs to create an `inge6.conf` to define all settings. An example is found in inge6.conf.example with the corresponding explanations.

## OIDC

For the Open ID Connect protocol we need a file containing the allowed clients. These clients are defined in the `clients_file` setting in the settings file. An example of such a file is found under `clients.json.example`. Finally, one needs to setup a public-private keypair for signing and verification of JWT tokens. Both locations configurable in the settings file.

In short, setup these files:

- `clients_file`, location configurable in the settings.
- `rsa_private_key`, for JWT token signing. Location configurable in the settings
- `rsa_public_key`, for JWT token verification. Location configurable in the settings

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

Redis is the store of this service. It is used to temporarily store data acquired during the BSN retrieval process. A redis-server should be setup, and the configuration should be copied in the settings file under the `redis` header. There is a Redis instance included in the [docker-compose.yml](../docker-compose.yml).

## SSL (local development)

An SSL connection is usually required, also in a development environment. To set this up, please define where to find the certificates and keys in the settings file under the `ssl` header.

## npm

This project requires frontend assets to be built using npm.
If you wish to run npm on your local machine, you must install both Node.js and npm. In this case you can follow the [npm installation instructions](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm). However, if you plan to use the Docker setup provided in this repository, there is no need to install npm manually, as it will be installed automatically when the containers are built.

Since we use GitHub as an npm repository, you must configure your GitHub token in your user's `~/.npmrc` file to install dependencies using `npm install`. While it is possible to place the `.npmrc` file in the project directory, it is recommended to place it in your home directory for reuse across multiple projects. An example `.npmrc` file (`.npmrc.example`) is available, which you can copy. Simply paste your token into this file to make it functional. Ensure you copy both lines from the `.npmrc.example` file:

1. The first line, starting with `@minvws:registry`, specifies that npm packages should be downloaded from the GitHub Package Registry (GPR) instead of the standard npm registry (npmjs.org).
2. The second line is required to enable package installation from GPR in an authenticated context.

For more information on authenticating to GitHub Packages, refer to the official documentation: [Configuring npm for use with GitHub Packages](https://docs.github.com/en/packages/using-github-packages-with-your-projects-ecosystem/configuring-npm-for-use-with-github-packages)

In short:

1. Copy the contents of `.npmrc.example` to `~/.npmrc`.
2. [Generate a GitHub token](https://github.com/settings/tokens/new?scopes=read:packages&description=GitHub+Packages+token) with, - at least - the `read:packages` scope.
3. Open your `.npmrc` file and replace `<YOUR_GITHUB_TOKEN>` with your GitHub token.    ```

## Setup Instructions

There are two different setup methods available to run this project:

1. **Docker**: Use a preconfigured Docker container for development. This includes Python, Node JS and npm.
2. **Local**: Install tools like Python and npm directly from your local machine. This requires manual setup of Python, Node JS and npm.

### Requirements

An exact overview of tools per setup method can be found below:

| Tool             | docker            | local               |
|------------------|-------------------|---------------------|
| docker           | ✔️                | ✔️                  |
| docker compose   | ✔️                | ✔️                  |
| openssl          | ✔️                | ✔️                  |
| gnu make         | ✔️                | ✔️                  |
| python           |                   | ✔️                  |
| npm              |                   | ✔️                  |
| node js          |                   | ✔️                  |
| curl             | ✔️                | ✔️                  |

### 1. Remote Docker Container

#### Steps

1. Prepare the `.npmrc` file with the instructions described earlier in this document.
2. Build the project: `make setup-remote`
3. Run the service: `make run-remote`

### 2. Local Installation

#### Dependencies

Make sure to install the following dependencies:

```bash
sudo apt-get update && sudo apt-get install libxmlsec1-dev
```

#### Steps

1. Prepare the `.npmrc` file with the instructions described earlier in this document.
2. Set up the project: `make setup-local`
3. Run the service: `make run-local`

## Contributions

When contributing to inge6 a few Make commands should be considered to make sure linting, type-checking (MyPy) and tests are still valid:

- `make lint`, check linting using pylint.
- `make check-type`, check that typing is done correctly. Also, see 'MyPy: stubs'.
- `make test`, run the tests

or

- `make check-all`, to check all the above

## MyPy: stubs

To make use of our custom stubs when running mypy make sure you have correctly exported the env variable:

```bash
export MYPYPATH=~/work/myproject/stubs
```
