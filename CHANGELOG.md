# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and (starting from v1.0.0) this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
