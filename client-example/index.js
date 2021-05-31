const { Issuer, generators } = require('openid-client');
const https = require('https')
const express = require('express');
const url = require('url');

const app = express()
const port = 3000

const host = "10.48.118.250";
const baseUrl = `https://${host}:8006`;
// const host = "tvs-connect.coronacheck.nl";
// const baseUrl = `https://${host}`;

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
var state;

app.get('/', (req, res) => {
  // res.send('Hello World');
  res.sendFile('index.html', {root: './'});
});

app.get('/finished', (req, res) => {
  // res.send('Hello World');
  at = req.query.at

  const buff = Buffer.from(at, 'base64');
  const jsoned = buff.toString('utf-8');

  parsed_json = JSON.parse(jsoned)

  // console.log(jsoned)
  // id_token = parsed_json.id_token
  // const id_token_buff = Buffer.from(id_token, 'utf-8')
  // const b64_id_token = id_token_buff.toString('base64')
  // console.log(b64_id_token, id_token)

  const new_req = https.request({
    hostname: host,
    port: 8006,
    path: '/bsn_attribute',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': jsoned.length,
      'Authorization': `Bearer ${parsed_json.id_token}`
    }
  }, new_res => {
    console.log(`statusCode: ${new_res.statusCode}`)

    new_res.on('data', d => {
      process.stdout.write(d)

      html = `
      <h1> Successfully achieved token: </h1>
      <pre>${jsoned}</pre>
      <p>${d}</p>
      `
      res.send(html)
    })
  })

  new_req.on('error', error => {
    console.error(error)
  })

  new_req.write(jsoned)
  new_req.end()

});

app.get('/login', (req, res) => {
  if ('code' in req.query ) {
    // console.log(req);
    const params = client.callbackParams(req);
    console.log(params);
    client.callback(redirect_uri, params, { code_verifier, state }) // => Promise
      .then(function (tokenSet) {
        console.log('received and validated tokens %j', tokenSet);
        console.log('validated ID Token claims %j', tokenSet.claims());

        jsoned = JSON.stringify(tokenSet);
        let buff = Buffer.from(jsoned, 'utf-8');
        let text = buff.toString('base64');

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
          redirect_uris: [redirect_uri],
          response_types: ['code'],
          id_token_signed_response_alg: "RS256",
          token_endpoint_auth_method: "none"
        });

        // !!!! CARE: EXAMPLE DOES NOT IMPLEMENT THIS SECURITY ASPECT:
        // store the code_verifier in your framework's session mechanism, if it is a cookie based solution
        // it should be httpOnly (not readable by javascript) and encrypted.
        code_verifier = generators.codeVerifier();
        state = generators.state()

        code_challenge = generators.codeChallenge(code_verifier);

        authorizationUrl = client.authorizationUrl({
          scope: 'openid',
          resource: baseUrl + '/authorize',
          state: state,
          code_challenge,
          code_challenge_method: 'S256',
        });
      }, (error) => {
        console.log(error);
      });
}