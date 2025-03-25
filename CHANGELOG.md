# Changelog

All notable changes to this project will be documented in this file (Online version can be in the GitHub repository).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and (starting from v1.0.0) this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.3.7] 2022-02-21

## What's Changed

- when mocking and auth_by_proxy is disabled, an error is raised. But a… by @maxxiefjv in <https://github.com/91divoc-ln/inge-6/pull/290>
- Bump mypy from 0.921 to 0.931 by @dependabot in <https://github.com/91divoc-ln/inge-6/pull/272>
- Bump pytest-asyncio from 0.16.0 to 0.18.1 by @dependabot in <https://github.com/91divoc-ln/inge-6/pull/295>
- Bump types-requests from 2.26.2 to 2.27.10 by @dependabot in <https://github.com/91divoc-ln/inge-6/pull/296>
- Bump uvicorn from 0.16.0 to 0.17.5 by @dependabot in <https://github.com/91divoc-ln/inge-6/pull/297>
- Bump types-redis from 4.0.4 to 4.1.16 by @dependabot in <https://github.com/91divoc-ln/inge-6/pull/298>
- Bump pytest-mock from 3.6.1 to 3.7.0 by @dependabot in <https://github.com/91divoc-ln/inge-6/pull/302>
- Bump pytest-redis from 2.3.0 to 2.4.0 by @dependabot in <https://github.com/91divoc-ln/inge-6/pull/301>
- Bump black from 21.12b0 to 22.1.0 by @dependabot in <https://github.com/91divoc-ln/inge-6/pull/300>
- Bump bandit from 1.7.1 to 1.7.2 by @dependabot in <https://github.com/91divoc-ln/inge-6/pull/299>

## [v1.3.6] 2021-12-22

## What's Changed

- Bump mypy from 0.910 to 0.921 by @dependabot in <https://github.com/91divoc-ln/inge-6/pull/256>
- Bump types-redis from 4.0.4 to 4.0.5 by @dependabot in <https://github.com/91divoc-ln/inge-6/pull/257>
- improve log messages and start logging empty redirect query params by @maxxiefjv in <https://github.com/91divoc-ln/inge-6/pull/255>
- add changelog to changelog.md by @maxxiefjv in <https://github.com/91divoc-ln/inge-6/pull/261>
- Machtigen sorry page when not available by @maxxiefjv in <https://github.com/91divoc-ln/inge-6/pull/254>
- form should be a GET method by @maxxiefjv in <https://github.com/91divoc-ln/inge-6/pull/260>

## [v1.3.5] 2021-12-21

- fix redirect to sorry page issues

## [v1.3.4] 2021-12-18

- soft validation scopes instead of throwing exceptions
- add validUntil to metadata
- add JWT libsodium key generation in README.md

## [v1.3.3] 2021-12-02

- Update default machtigen/scoping settings

## [v1.3.2] 2021-11-25

### Added

- add some additional information on code_verifiers and code_challenge in README.md
- Scoping/Machtigen support for different environments
- DigiD Machtigen tracking throughout user lifecycle

### Changed

- Set permissions for generated directories
- No longer mention the services used (i.e. don't show redis in client error messages)

### Fixed

- fix getting wrong attribute from ArtifactResponse SAML
- Fix open redirect, doing so by adding several top-level exception handlers

## [v1.3.1] 2021-10-26

### Added

- perform machtigen on scope change 

### Changed

- Code formatting with black by

## [v1.3.0] 2021-10-25

### Added

- Clustered connection support.
- Add outage checking. If ratelimit.outage_key has been set, this key is checked to determine if an outage should be reported
- Better templating mechanism. No longer needed to have the templates locally, but is included in installation
- Better compatibility when using inge6/MAX as a dependency (getting rid of globals, packaging the templates, adding response models)
- Added support for scoping in the SAML library

## [v1.1.2] 2021-09-21

### Fixed

- hotfix redis creating 6 new connections per thread.


## [v1.1.1] - 2021-09-12

### Added

- Redis debugger, ability to log unresolved artifacts and other unretrieved values in redis.

### Fixed

- User limit of 0 is still a user limit, before a limit of zero was not working
- The SAML issuer and inge6 issuer are now seperated in the config, solving the issue regarding the openid-configuration discovery

- New config:

```
[saml]
# The domain which contains the subdomains of the configured Identity providers
base_issuer = localhost:8007
```

- Config change:

```
[DEFAULT]
# Needs to be a https full URL
issuer = https://10.48.118.250:8006
```

## [v1.1.0] - 2021-09-08

### Added

- added expected redis key value pairs explanation in the README

### Changed

- config setting `connect_to_idp_key` to `primary_idp_key`.
- config setting definition of `issuer`. This is just the domain, without https or http and subdomain

### Fixed

- update entity and urls for digid metadata
- mock was creating nonsense requests, keep state in RelayState
- optional mock_digid setting (#104)

## [v1.0.0] - 2021-08-26

### Added

- Support for multiple IDP configurations
- Overflow to secondary IDP when primary is full
- set primary IDP in redis
- endpoints configurable
- file existence checks on startup

- config additions:

```text
    [DEFAULT]
    connect_to_idp_key = tvs:connect_to_idp
    overflow_idp_key = tvs:overflow_idp

    authorize_endpoint = /authorize
    accesstoken_endpoint = /accesstoken
    jwks_endpoint = /jwks
    health_endpoint = /health
    loglevel = debug

    [ratelimt]
    user_limit_key_overflow_idp = digid_connect_user_limit

    [saml]
    identity_provider_settings = saml/identity_providers.json
```
