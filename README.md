# Setup

To run this service make sure you have the following files in place:
1. `saml/certs/sp.crt`
2. `saml/certs/sp.key`
3. Create a `settings.json` from the `settings-dist.json` having:
    - Attribute value as expected by the IdP
    - An assertionConsumerService URL representing your service url with a reference to the ACS

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
