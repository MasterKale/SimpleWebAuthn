const https = require('https');
const fs = require('fs');

const express = require('express');

const {
  // Registration ("Attestation")
  generateAttestationOptions,
  verifyAssertionResponse,
  // Login ("Assertion")
  generateAssertionOptions,
  verifyAttestationResponse,
} = require('@webauthntine/server');

const app = express();
const host = '0.0.0.0';
const port = 443;

app.use(express.static('./public/'));
app.use(express.json());

// Domain where the WebAuthn interactions are expected to occur
const origin = 'dev.dontneeda.pw';
// GENERATE A NEW VALUE FOR THIS EVERY TIME! The server needs to temporarily remember this value,
// so don't lose it until after you verify
const randomChallenge = 'totallyUniqueValueEveryTime';
// Your internal, _unique_ ID for the user (uuid, etc...). Avoid using identifying information here,
// like an email address
const userId = 'webauthntineInternalUserId';
// A username for the user
const username = 'user@webauthntine.foo';

app.get('/generate-attestation-options', (req, res) => {
  res.send(generateAttestationOptions(
    'WebAuthntine Example',
    origin,
    randomChallenge,
    userId,
    username,
  ));
});

app.post('/verify-attestation', (req, res) => {
  const { body } = req;

  console.log('verifying:', body);
});

app.post('/verify-registration', (req, res) => {
  const { body } = req;
});

https.createServer({
  key: fs.readFileSync('./dev.dontneeda.pw.key'),
  cert: fs.readFileSync('./dev.dontneeda.pw.crt'),
}, app).listen(port, host, () => {
  console.log(`🚀 Server ready at https://${host}:${port}`);
});
