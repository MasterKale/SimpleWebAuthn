/**
 * An example Express server showing off a simple integration of @webauthntine/server.
 *
 * The webpages served from ./public use @webauthntine/browser.
 */
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
    /**
     * After an attestation, the following authenticator info returned by
     * verifyAttestationResponse() should be persisted somewhere that'll tie it back to the user
     * specified during attestation:
     *
     * {
     *   base64PublicKey: string,
     *   base64CredentialID: string,
     *   counter: number,
     * }
     *
     * After an assertion, the `counter` value above should be updated to the value returned by
     * verifyAssertionResponse(). This method will also return a credential ID of the device that
     * needs to have its `counter` value updated.
     *
     */
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

  const { verified, authenticatorInfo } = verification;

  if (verified) {
    const { base64PublicKey, base64CredentialID, counter } = authenticatorInfo;
    const user = inMemoryUserDeviceDB[userId];
    const existingDevice = user.find((device) => device.base64CredentialID === base64CredentialID);

    if (!existingDevice) {
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

  let dbAuthenticator;
  // "Query the DB" here for an authenticator matching `base64CredentialID`
  Object.values(inMemoryUserDeviceDB).forEach((userDevs) => {
    for(let dev of userDevs) {
      if (dev.base64CredentialID === body.base64CredentialID) {
        dbAuthenticator = dev;
        return;
      }
    }
  });

  const verification = verifyAssertionResponse(body, `https://${origin}`, dbAuthenticator);

  const { verified, authenticatorInfo } = verification;

  if (verified) {
    // Update the authenticator's counter in the DB to the newest count in the assertion
    dbAuthenticator.counter = authenticatorInfo.counter;
  }

  res.send({ verified })
});

https.createServer({
  /**
   * You'll need to provide a SSL cert and key here because
   * WebAuthn can only be run from HTTPS:// URLs
   *
   * HINT: If you create a `dev` subdomain A-record that points to 127.0.0.1,
   * you can manually generate an HTTPS certificate for it using Let's Encrypt certbot.
   */
  key: fs.readFileSync('./dev.yourdomain.com.key'),
  cert: fs.readFileSync('./dev.yourdomain.com.crt'),
}, app).listen(port, host, () => {
  console.log(`🚀 Server ready at https://${host}:${port}`);
});
