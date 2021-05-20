# In this document the different types of requests are outlined:

For each endpoint the parameters are documented. Please use as described.

# `/authorize`
The authorize request is defined for clients to create a session with which they can login onto DigiD via the ToegangVerleningService (TVS). This can later be used to request attributes from DigiD.

### `client_id`:
each client is supposed to be registered to the system, and has a whitelisted set of response_types and redirect_uris. These are the values allowed to be used in the remaining query parameters.

### `response_type`:
For this application we only support the `id_token`, this is a signed JSON Web Token (JWT) allowing you to retrieve the artifact from the TVS services.

### `redirect_uri`:
This whitelisted value is used to redirect on success. Make sure that the client of this service is registered with the requested redirect_uri.

### `state`:
"Opaque value used to maintain state between the request and the callback. Typically, Cross-Site Request Forgery (CSRF, XSRF) mitigation is done by cryptographically binding the value of this parameter with a browser cookie." - https://openid.net/specs/openid-connect-core-1_0.html

### `nonce`:
"String value used to associate a Client session with an ID Token, and to mitigate replay attacks. The value is passed through unmodified from the Authentication Request to the ID Token. Sufficient entropy MUST be present in the nonce values used to prevent attackers from guessing values." - https://openid.net/specs/openid-connect-core-1_0.html

### Example request:
An example of an authorize request containing all the necessary parameters has the following structure:
```bash
GET /authorize?
    client_id=test_user
    &response_type=id_token
    &redirect_uri=https://client.your-requested-response-uri
    &scope=openid%20profile
    &state=af0ifjsldkj
    &nonce=n-0S6_WzA2Mj
```