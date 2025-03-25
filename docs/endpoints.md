# Open ID Connect requests to Inge6

Each of these requests are documented by the image above, and the documentation below. Please use as described.

## GET `/authorize`

The authorize request is defined for clients to create a session with which they can login onto DigiD via the ToegangVerleningService (TVS). This can later be used to request attributes from DigiD.

### `client_id`

each client is supposed to be registered to the system, and has a whitelisted set of response_types and redirect_uris. These are the values allowed to be used in the remaining query parameters.

### `response_type`

For this application we only support the `id_token`, this is a signed JSON Web Token (JWT) allowing you to retrieve the artifact from the TVS services.

### `redirect_uri`

This whitelisted value is used to redirect on success. Make sure that the client of this service is registered with the requested redirect_uri.

### `scope`

"OpenID Connect Clients use scope values, as defined in Section 3.3 of OAuth 2.0 [RFC6749], to specify what access privileges are being requested for Access Tokens" - <https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims>

### `state`

"Opaque value used to maintain state between the request and the callback. Typically, Cross-Site Request Forgery (CSRF, XSRF) mitigation is done by cryptographically binding the value of this parameter with a browser cookie." - <https://openid.net/specs/openid-connect-core-1_0.html>

### `nonce`

"String value used to associate a Client session with an ID Token, and to mitigate replay attacks. The value is passed through unmodified from the Authentication Request to the ID Token. Sufficient entropy MUST be present in the nonce values used to prevent attackers from guessing values." - <https://openid.net/specs/openid-connect-core-1_0.html>

### Example request

An example of an authorize request containing all the necessary parameters has the following structure:

```bash
GET /authorize?
    client_id=test_user
    &response_type=id_token
    &redirect_uri=https://client.your-requested-response-uri
    &scope=openid%20profile
    &state=af0ifjsldkj
    &nonce=n-0S6_WzA2Mj
    &code_challenge=_1f8tFjAtu6D1Df-GOyDPoMjCJdEvaSWsnqR6SLpzsw
    &code_challenge_method=S256
```

## POST `/accesstoken`

### `code`

The code returned from the /authorize request.

### `code_verifier`

The code verifier used in the /authorize request to compute the code_challenge

### `client_id`

The client identifier used to verify

### `state`

The same state used in the /authorize request.

### `grant_type`

"An authorization grant is a credential representing the resource
owner's authorization (to access its protected resources) used by the
client to obtain an access token.  This specification defines four
grant types -- authorization code, implicit, resource owner password
credentials, and client credentials -- as well as an extensibility
mechanism for defining additional types." - (<https://datatracker.ietf.org/doc/html/rfc6749#section-1.3>)

### `redirect_uri`

Should be identical to the redirect_uri provided in the authorization request.

Ensure that the redirect_uri parameter value is identical to the redirect_uri parameter value that was included in the initial Authorization Request. If the redirect_uri parameter value is not present when there is only one registered redirect_uri value, the Authorization Server MAY return an error (since the Client should have included the parameter) or MAY proceed without an error (since OAuth 2.0 permits the parameter to be omitted in this case).

### Example of request

```bash
POST /accesstoken
Content-Type: application/x-www-form-urlencoded

    code=7f2fa9a48d8f4aef95a5fffb695d8f20
    &code_verifier=SoOEDN-mZKNhw7Mc52VXxyiqTvFB3mod36MwPru253c
    &state=af0ifjsldkj
    &client_id=test_client
    &grant_type=authorization_code
    &redirect_uri=localhost:8006/attrs
```

## GET `/bsn_attribute`

### Authorization Header

> AuthorizationAuthorization: Bearer 'id_token'

Where the id_token is a base64 encoded JWT token containing a signature by the Inge6 instance retrieved during the authorization code flow.
