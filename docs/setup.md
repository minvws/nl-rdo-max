# Setup

As MAX is an OIDC <-> SAML bridge, one has to have files for both. Each file is described below. Further, one needs to create a `max.conf` to define all settings. An example is found in `max.conf.example` with the corresponding explanations.

## OIDC

For the OpenID Connect protocol we need a file containing the allowed clients. These clients are defined in the `clients_file` setting in the settings file. An example of such a file is found under `clients.json.example`.

You need to configure supported login methods which are usually configured in `login_methods.json` (configured by the `login_methods_file_path` setting in `max.conf`). An example of such a file is found under `login_methods.json.example`.

Finally, one needs to setup a public-private keypair for signing and verification of JWT tokens. Both locations configurable in the settings file.

In short, setup these files (within and in addition to `max.conf` itself):

- `clients_file`, allowed clients, location and filename configurable in the settings
- `login_methods_file_path`, login methods, location and filename configurable in the settings
- `rsa_private_key`, for JWT token signing, location and filename configurable in the settings
- `rsa_public_key`, for JWT token verification, location and filename configurable in the settings

## SAML

SAML handles the communication between MAX and the IdP, short for Identity Provider, which is either [TVS](https://www.dictu.nl/toegangverleningservice) or [DigiD](https://www.logius.nl/onze-dienstverlening/toegang/digid). To make this work we need to setup the SAML directory.

In the configured `identity_provider_settings` file, please make sure that these files are available for each IdP, and reference to the correct IdP files:

- `cert_path`, the certificate used for verifying our signed message. Passed along in requests
- `key_path`, the key used for signing SAML requests
- `settings_path`, a file containing the SAML settings for creating our metadata and requests, and parsing the IdP metadata. An example is provided in saml/settings-dist.json, this file also includes an explanation of the options.
- `idp_metadata_path`, the location of the metadata of the IdP

**note: each configured idp is expected to have a subdomain to the configured issuer (with TLS support).**

Template files (these are included in the repository):

- `sp_template`, saml/templates/xml/sp_metadata.xml
- `authn_request_template`, saml/templates/xml/authn_request.xml
- `artifactresolve_request_template`, saml/templates/xml/artifactresolve_request.xml
- `authn_request_html_template`, saml/templates/html/authn_request.html

## Redis

Redis is the store of this service. It is used to temporarily store data acquired during the BSN retrieval process. A redis-server should be setup, and the configuration should be copied in the settings file under the `redis` header. There is a Redis instance included in the [docker-compose.yml](../docker-compose.yml) file.

## SSL (local development)

An SSL connection is usually required, also in a development environment. To set this up, please define where to find the certificates and keys in the settings file under the `ssl` header.

## npm

This project requires frontend assets to be built using `npm`. If you wish to run `npm` on your local machine, you must install both Node.js and `npm`. In this case you can follow the [npm installation instructions](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm). However, if you plan to use the Docker setup provided in this repository, there is no need to install `npm` manually, as it will be installed automatically when the containers are built.

You can opt to build with, or without our official ui-theme:

### Building with @minvws/nl-rdo-rijksoverheid-ui-theme

Since we use GitHub as an NPM repository, you must configure your GitHub token in your user's `~/.npmrc` file to install dependencies using `npm install`. While it is possible to place the `.npmrc` file in the project directory, it is recommended to place it in your home directory for reuse across multiple projects. An example `.npmrc` file (`.npmrc.example`) is available, which you can copy. Simply paste your token into this file to make it functional. Ensure you copy both lines from the `.npmrc.example` file:

1. The first line, starting with `@minvws:registry`, specifies that npm packages which match the `@minvws` scope, should be downloaded from the GitHub Package Registry (GPR, npm.pkg.github.com) instead of the standard npm registry (npmjs.org).
2. The second line is required to enable package installation from GPR in an authenticated context.

For more information on authenticating to GitHub Packages, refer to the official documentation: [Configuring npm for use with GitHub Packages](https://docs.github.com/en/packages/using-github-packages-with-your-projects-ecosystem/configuring-npm-for-use-with-github-packages)

In short:

1. Copy the contents of `.npmrc.example` to `~/.npmrc`.
2. [Generate a GitHub token](https://github.com/settings/tokens/new?scopes=read:packages&description=GitHub+Packages+token) with, - at least - the `read:packages` scope.
3. Open your `.npmrc` file and replace `<YOUR_GITHUB_TOKEN>` with your GitHub token.

Note: When you run the various `make` commands later on, they will in turn eventually run `scripts/setup-npm.sh` which is a helper script that adds the necessary GitHub NPM registry and token line. That script will run non-interactively when you set a `GITHUB_TOKEN` environment variable. This is necessary when using `docker buildx`, not sure about regular `docker build`. If you don't set that, then the script will attempt to run interactively and prompt you for a token.

### Building without a ui-theme

You can also opt to build MAX without a ui-theme; in this way, you can build MAX without needing access to npm.pkg.github.com. This way you will have a working MAX, but unthemed and looking a bit basic. To do that, you need to uninstall the theme as follows:

```shell
npm uninstall @minvws/nl-rdo-rijksoverheid-ui-theme
```

The `scripts/setup-npm.sh` script will then detect that this package is not a part of the target installation and patch `app.js` and `app.scss` accordingly, allowing you to run an unthemed version of MAX.

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
| nodejs           |                   | ✔️                  |
| curl             | ✔️                | ✔️                  |

### 1. Docker Container

#### Steps

1. Prepare the `.npmrc` file with the instructions described earlier in this document.
2. Build the project: `make setup-remote`
3. Run the service: `make run-remote`

### 2. Local Installation

#### Dependencies

Make sure to install the following dependencies:

```shell
sudo apt-get update && sudo apt-get install libxmlsec1-dev
```

#### Steps

1. Prepare the `.npmrc` file with the instructions described earlier in this document.
2. Set up the project: `make setup-local`
3. Run the service: `make run-local`

## Contributions

When contributing to MAX, a few `make` commands should be considered to make sure linting, type-checking (MyPy) and tests are still valid:

- `make lint`, check linting using pylint.
- `make check-type`, check that typing is done correctly.
- `make test`, run the tests

or

- `make check-all`, to check all the above
