const { Issuer, generators } = require('openid-client');
const express = require('express');
const url = require('url');

const passport = require('passport');
const { OIDCStrategy } = require('passport-oidc-strategy');

const app = express()
const port = 3000

// const baseUrl = "http://localhost:8006";
// const baseUrl = "https://10.48.118.250:8006";
const baseUrl = "https://tvs.acc.coronacheck.nl";

const clientBaseUrl = "https://e039d10f9c39.ngrok.io";
const redirect_uri = clientBaseUrl + "/login";
const finished_redirect_uri = clientBaseUrl + "/finished";

var authorizationUrl;
var client;
var code_verifier;
var code_challenge;

app.get('/', (req, res) => {
  // res.send('Hello World');
  res.sendFile('index.html', {root: './'});
});

app.get('/finished', (req, res) => {
  // res.send('Hello World');
  res.send('Loop Done.');
});

app.get('/login', (req, res) => {
  if ('code' in req.query ) {
    // console.log(req);
    const params = client.callbackParams(req);

    client.callback(redirect_uri, params, { code_verifier }) // => Promise
      .then(function (tokenSet) {
        console.log('received and validated tokens %j', tokenSet);
        console.log('validated ID Token claims %j', tokenSet.claims());
        // s = body.exp.toUTCString();

        jsoned = JSON.stringify(tokenSet);
        let buff = Buffer.from(jsoned, 'utf-8');
        let text = buff.toString('base64');
        res.cookie('access_token', text);
        res.redirect(baseUrl + `/login-digid?redirect_uri=${finished_redirect_uri}&at=${text}`) // TODO: Token in redirect
        // res.redirect(baseUrl + '/login-digid') // TODO: Token in redirect
      }, (error) => {
        console.log(error);
      });

  } else {
    res.redirect(authorizationUrl);
  }
});

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
  discoverTvsDigiD();
});

function discoverTvsDigiD() {
  Issuer.discover(baseUrl + '/.well-known/openid-configuration') // => Promise
    .then( (issuer) => {
        console.log('Discovered issuer %s %O', issuer.issuer, issuer.metadata);

        client = new issuer.Client({
          client_id: 'test_client',
          redirect_uris: [redirect_uri],
          response_types: ['code'],
          id_token_signed_response_alg: "RS256",
          token_endpoint_auth_method: "none"
        });

        // !!!! CARE: EXAMPLE DOES NOT IMPLEMENT THIS SECURITY ASPECT:
        // store the code_verifier in your framework's session mechanism, if it is a cookie based solution
        // it should be httpOnly (not readable by javascript) and encrypted.
        code_verifier = generators.codeVerifier();

        code_challenge = generators.codeChallenge(code_verifier);

        authorizationUrl = client.authorizationUrl({
          scope: 'openid',
          resource: baseUrl + '/authorize',
          code_challenge,
          code_challenge_method: 'S256',
        });
      }, (error) => {
        console.log(error);
      });
}