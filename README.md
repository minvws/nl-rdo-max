# nl-covid-19-coronacheck-access-holder-glue-service (internallyt known as Inge 6)

*NOTE: This repository is a work in progress. If you plan to make non-trivial changes, we recommend to open an issue beforehand where we can discuss your planned changes.**

This system is basicaly some openID glue between the citizen apps and the DICTU Toegangs Verlenings Service.
 
### Inge

Note that internally the systems used the names 'Inge-##'; where ## was some sequal number. As the course of the pandemic was unpredictable and often changed - some of those numbers never saw the light of day. For the DCC and Domestic certificates the two key systems (in addition to the website, the RIVM/GGD systems relied on, etc, etc) are the signing service (nl-covid-19-coronacheck-backend-bizrules-signing-service - internally known as inge number 4) and the nl-covid-19-coronacheck-access-holder-glue-service (build number 6).

# Setup

To run this service make sure you have the following files in place:
1. `saml/certs/sp.crt`
2. `saml/certs/sp.key`
3. Create a `saml/settings.json` from the `saml/settings-dist.json` having:
    - Attribute value as expected by the IdP
    - An assertionConsumerService URL representing your service url with a reference to the ACS
4. For RSA signing of the OIDC cookies we need an RSA keypair. For now generate one, and put into
the folder: secrets/private_unencrypted.pem
5. Add your domain to the response_uris list in the clients.json.
6. Have ssl certificates in your secrets/ssl/private and /certs folder, and point to them in the config file.

Setup a redis server, and set the host and port in `inge-6/config.py`.

Next, with the appropriate host and port, run in your environment:
```bash
$ sh run_server.sh
```


# Developers setup
Make sure you followed the steps for the regular Setup, then run:
```bash
$ make fresh
...
$ sh run_server.sh
```


# MyPy: stubs
To make use of our custom stubs when running mypy make sure you have correctly exported the env variable
```bash
$ export MYPYPATH=~/work/myproject/stubs
```


## Development & Contribution process

The development team works on the repository in a private fork (for reasons of compliance with existing processes) and shares its work as often as possible.

If you plan to make non-trivial changes, we recommend to open an issue beforehand where we can discuss your planned changes. This increases the chance that we might be able to use your contribution (or it avoids doing work if there are reasons why we wouldn't be able to use it).

Note that all commits should be signed using a gpg key.

## Security

Security issues can be reported through a github issue, at https://coronacheck.nl/nl/kwetsbaarheid-melden or confidentially through the https://www.ncsc.nl/contact/kwetsbaarheid-melden.


