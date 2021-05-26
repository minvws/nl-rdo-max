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
uvicorn inge-6.main:app --host 0.0.0.0 --port 8006
```


# Developers setup
Make sure you followed the steps for the regular Setup, then run:
```bash
$ make fresh
...
$ sh run_server.sh
```
