require('dotenv').config()
const { Issuer, generators } = require('openid-client');
const { createHash, randomBytes } = require('crypto');
const base64url = require('base64url')

const https = require('https')
const express = require('express');

const app = express()
const port = 3000

const baseUrl = `https://${process.env.SERVER_HOST}:${process.env.SERVER_PORT}`;
const baseUrlBrowser = `https://${process.env.SERVER_HOST_BROWSER}:${process.env.SERVER_PORT}`;


const clientBaseUrl = process.env.CLIENT_BASE_URL 
const redirect_uri = clientBaseUrl + "/login";
const finished_redirect_uri = clientBaseUrl + "/finished";

var authorizationUrl;
var client = null;
var code_verifier;
var code_challenge;
var state, nonce;

app.get('/', (req, res) => {
  res.sendFile('index.html', {root: './'});
});

app.get('/finished', (req, res) => {
  at = req.query.at

  const buff = Buffer.from(at, 'base64');
  const jsoned = buff.toString('utf-8');

  parsed_json = JSON.parse(jsoned)

  const new_req = https.request({
    hostname: process.env.SERVER_HOST,
    port: process.env.SERVER_PORT,
    path: '/bsn_attribute',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': 0,
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
    html = `
    <h1> Failed to achieve bsn: </h1>
    <pre>${error}</pre>
    `
    res.send(html)
  })

  new_req.write('')
  new_req.end()

});

app.get('/login', (req, res) => {
  if ('code' in req.query ) {
    // console.log(req);
    const params = client.callbackParams(req);
    console.log(params);
    client.callback(redirect_uri, params, { code_verifier, state, nonce }) // => Promise
      .then(function (tokenSet) {
        console.log('received and validated tokens %j', tokenSet);
        console.log('validated ID Token claims %j', tokenSet.claims());

        jsoned = JSON.stringify(tokenSet);
        let buff = Buffer.from(jsoned, 'utf-8');
        let text = buff.toString('base64');

        res.redirect('/finished?at=' + text)
      }, (error) => {
        console.log(error)
        html = `
        <h1> Failed to achieve token: </h1>
        <pre>${error}</pre>
        <a href='/'> Try again </a>
        `
        res.send(html)
      });

  } else if ('error' in req.query) {
    html = `
    <h1> Something went wrong: </h1>
    <ul>
      <li> <b>error:</b> ${req.query['error']} </li>
      <li> <b>error_description:</b> ${req.query['error_description']} </li>
      <li> <b>state:</b> ${req.query['state']} </li>
    </ul>
    `
    res.send(html)
  } else {
    // !!!! CARE: EXAMPLE DOES NOT IMPLEMENT THIS SECURITY ASPECT:
    // store the code_verifier in your framework's session mechanism, if it is a cookie based solution
    // it should be httpOnly (not readable by javascript) and encrypted.
    state = generators.state()
    nonce = generators.nonce()

    code_verifier = generators.codeVerifier()
    code_challenge = generators.codeChallenge(code_verifier)
    console.log(`resource url ${baseUrlBrowser + '/authorize'}`)
    authorizationUrl = client.authorizationUrl({
      scope: 'openid',
      resource: baseUrlBrowser + '/authorize',
      state: state,
      code_challenge,
      code_challenge_method: 'S256',
      nonce: nonce
    });
    authorizationUrl = baseUrlBrowser + '/' + authorizationUrl.split('/').slice(-1)[0]
    console.log(`authorization url ${authorizationUrl}`)
    res.redirect(authorizationUrl);
  }
});

app.listen(port, () => {
  console.log(`Example app listening at ${process.env.CLIENT_BASE_URL}:${port}`);
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

      }, (error) => {
        console.log(error);
        setTimeout(discoverTvsDigiD, 2000); // Automatic retry
      });
}
