# System summary


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


