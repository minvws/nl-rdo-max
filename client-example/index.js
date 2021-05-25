const { Issuer, generators } = require('openid-client');
const passport = require('passport');
const { OIDCStrategy } = require('passport-oidc-strategy');


baseUrl = "http://localhost:8006";

// const issuer = new Issuer({
//   issuer: baseUrl,
//   authorization_endpoint: baseUrl + '/authorize',
//   token_endpoint: baseUrl + '/accesstoken',
//   jwks_uri: baseUrl + '/jwks',
//   userinfo_endpoint: baseUrl + '/userinfo'
// });

// const client_id = 'test_client';
// const client = new issuer.Client({
//   client_id: client_id,
//   redirect_uris: [baseUrl],
//   response_types: ['code'],
//   id_token_signed_response_alg: "RS256",
//   token_endpoint_auth_method: "none"
// });

// client.pushedAuthorizationRequest({
//   client_id: client_id
// }).then( (authorizationRequestResponse) => {
//   console.log(authorizationRequestResponse)
// }, (error) => {
//   console.log(error)
// });

// const code_verifier = generators.codeVerifier();
// // store the code_verifier in your framework's session mechanism, if it is a cookie based solution
// // it should be httpOnly (not readable by javascript) and encrypted.

// const code_challenge = generators.codeChallenge(code_verifier);

// client.authorizationUrl({
//   scope: 'openid',
//   resource: baseUrl + '/authorize',
//   code_challenge,
//   code_challenge_method: 'S256',
// });

// const params = client.callbackParams(req);

// client.callback(baseUrl, params, { code_verifier }) // => Promise
//   .then(function (tokenSet) {
//     console.log('received and validated tokens %j', tokenSet);
//     console.log('validated ID Token claims %j', tokenSet.claims());
//   });

// ././//////

// Issuer.discover(baseUrl + '/.well-known/openid-configuration') // => Promise
//   .then( (issuer) => {
//     console.log('Discovered issuer %s %O', issuer.issuer, issuer.metadata);
//     const client = new issuer.Client({
//       client_id: 'test_client',
//       redirect_uris: [baseUrl],
//       response_types: ['code'],
//       id_token_signed_response_alg: "RS256",
//       token_endpoint_auth_method: "none"
//     });

//     const code_verifier = generators.codeVerifier();
//     // store the code_verifier in your framework's session mechanism, if it is a cookie based solution
//     // it should be httpOnly (not readable by javascript) and encrypted.
  
//     const code_challenge = generators.codeChallenge(code_verifier);
  
//     client.authorizationUrl({
//       scope: 'openid',
//       resource: baseUrl + '/authorize',
//       code_challenge,
//       code_challenge_method: 'S256',
//     });
  
//     const params = client.callbackParams(req);
  
//     client.callback(baseUrl, params, { code_verifier }) // => Promise
//       .then(function (tokenSet) {
//         console.log('received and validated tokens %j', tokenSet);
//         console.log('validated ID Token claims %j', tokenSet.claims());
//       });
//   }, (error) => {
//     throw error;
//   });

// const tvsDigiDIssuer = new Issuer({
//   issuer: baseUrl,
//   authorization_endpoint: baseUrl + '/authorize',
//   token_endpoint: baseUrl + '/acesstoken',
//   userinfo_endpoint: baseUrl + '/userinfo',
//   jwks_uri: baseUrl + '/jwks'
// });

(async () => {
  const tvsDigiDIssuer = await Issuer.discover(baseUrl + '/.well-known/openid-configuration')
  
  // const tvsDigiDClient = new tvsDigiDIssuer.Client({
  //   client_id: 'test_client',
  //   token_endpoint_auth_method: 'none'
  // });
  
  // const tvsDigidParams = {
  //   redirect_uri: 'http://localhost:8006/',
  //   scope: 'openid'
  // };
  
  // const passReqToCallback = true;
  
  // passport.use('tvsDigiD', new OIDCStrategy({ client: tvsDigiDClient, params: tvsDigidParams, passReqToCallback: passReqToCallback }, (req, tokenset, userinfo, done) => {
  //   console.log('tokenset', tokenset);
  //   console.log('access_token', tokenset.access_token);
  //   console.log('id_token', tokenset.id_token);
  //   console.log('claims', tokenset.claims);
  //   console.log('userinfo', userinfo);
   
  //   // I don't have this in my code, I'm just interested in seeing the console output right now before incorporating the user model.
  //   /*
  //   models.User.findOne({ id: tokenset.claims.sub }, function (err, user) {
  //     if (err) return done(err);
  //     return done(null, user);
  //   });*/
  
  //   return done(err);
  
  // }));
})();