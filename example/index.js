const https = require('https');
const fs = require('fs');

const express = require('express');

const {
  // Registration ("Attestation")
  generateAttestationOptions,
  verifyAttestationResponse,
  // Login ("Assertion")
  generateAssertionOptions,
  verifyAssertionResponse,
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

const inMemoryUserDeviceDB = {
  [userId]: [
    {
      base64PublicKey: undefined,
      base64CredentialID: undefined,
      counter: -1,
    }
],
};

/**
 * Registration (a.k.a. "Attestation")
 */
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

  const verification = verifyAttestationResponse(body, `https://${origin}`);

  console.log('verification:', verification);

  const { verified, authenticatorInfo } = verification;

  if (verified) {
    const { base64PublicKey, base64CredentialID, counter } = authenticatorInfo;
    const user = inMemoryUserDeviceDB[userId];
    const existingDevice = user.find((device) => device.base64CredentialID === base64CredentialID);

    if (existingDevice) {
      console.log('device already exists, skipping insertion');
      console.debug(existingDevice);
    } else {
      console.log(`storing public key, credential ID, and counter for ${userId}`);

      inMemoryUserDeviceDB[userId].push({
        base64PublicKey,
        base64CredentialID,
        counter,
      });
    }
  }

  res.send({ verified });
});

/**
 * Login (a.k.a. "Assertion")
 */
app.get('/generate-assertion-options', (req, res) => {
  // You need to know the user by this point
  const user = inMemoryUserDeviceDB[userId];

  res.send(generateAssertionOptions(
    randomChallenge,
    user.map(data => data.base64CredentialID),
  ));
});

app.post('/verify-assertion', (req, res) => {
  const { body } = req;

  console.log('verifying assertion:', body);
});

https.createServer({
  key: fs.readFileSync('./dev.dontneeda.pw.key'),
  cert: fs.readFileSync('./dev.dontneeda.pw.crt'),
}, app).listen(port, host, () => {
  console.log(`🚀 Server ready at https://${host}:${port}`);
});
