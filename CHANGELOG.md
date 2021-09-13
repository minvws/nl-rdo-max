# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and (starting from v1.0.0) this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.1.1] - 2021-09-12

### Added
- Redis debugger, ability to log unresolved artifacts and other unretrieved values in redis. Optionally, the `debug_keytype_key` setting may contain the name of the key in redis holding the prefix for the keys to watch for expiration.

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
- Overflow to secundairy IDP when primary is full
- set primary IDP in redis
- endpoints configurable
- file existence checks on startup

- config additions:
```
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
