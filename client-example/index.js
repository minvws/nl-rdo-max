const { Issuer, generators } = require('openid-client');
const express = require('express');
const url = require('url');

const app = express()
const port = 3000

// const baseUrl = "http://localhost:8006";
const baseUrl = "https://10.48.118.250:8006";
// const baseUrl = "https://tvs.acc.coronacheck.nl";

const clientBaseUrl = "https://e039d10f9c39.ngrok.io";
const redirect_uri = clientBaseUrl + "/login";
const redirect_uris = [
  clientBaseUrl + "/login",
  "http://10.48.118.250:3000" + "/login",
]
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
  at = req.query.at

  const buff = Buffer.from(at, 'base64');
  const jsoned = buff.toString('utf-8');

  html = `
    <h1> Successfully achieved token: </h1>
    <pre>${jsoned}</pre>
  `
  res.send(html)
});

app.get('/login', (req, res) => {
  if ('code' in req.query ) {
    // console.log(req);
    const params = client.callbackParams(req);

    client.callback(redirect_uri, params, { code_verifier }) // => Promise
      .then(function (tokenSet) {
        console.log('received and validated tokens %j', tokenSet);
        console.log('validated ID Token claims %j', tokenSet.claims());

        jsoned = JSON.stringify(tokenSet, null, 2);
        let buff = Buffer.from(jsoned, 'utf-8');
        let text = buff.toString('base64');
        console.log(tokenSet.claims());
        res.redirect('/finished?at=' + text)
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
          redirect_uris: redirect_uris,
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