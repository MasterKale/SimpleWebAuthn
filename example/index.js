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

/**
 * RP ID represents the "scope" of websites on which a authenticator should be usable. The Origin
 * represents the expected URL from which an attestation or assertion occurs.
 */
const rpID = 'dev.yourdomain.com';
const origin = `https://${rpID}`;
/**
 * A new, random value needs to be generated every time an attestation or an assertion is performed!
 * The server needs to temporarily remember this value for verification, so don't lose it until
 * after you verify an authenticator response.
 */
const randomChallenge = 'totallyUniqueValueEveryTime';
/**
 * WebAuthn expects you to be able to uniquely identify the user that performs an attestation or
 * assertion. The user ID you specify here should be your internal, _unique_ ID for that user
 * (uuid, etc...). Avoid using identifying information here, like email addresses, as it may be
 * stored within the authenticator.
 */
const userId = 'webauthntineInternalUserId';
/**
 * The username can be a human-readable name, email, etc... as it is intended only for display.
 */
const username = 'user@yourdomain.com';

/**
 * You'll need a database to store a few things:
 *
 * 1. Users
 *
 * You'll need to be able to associate attestations and assertions to a specific user
 *
 * 2. Challenges
 *
 * The totally-random-unique-every-time values you pass into every execution of
 * `generateAttestationOptions()` or `generateAssertionOptions()` MUST be stored until
 * `verifyAttestationResponse()` or `verifyAssertionResponse()` (respectively) is called to verify
 * a response.
 *
 * These values only need to be persisted for `timeout` number of milliseconds (see the `generate`
 * methods.)
 *
 * 3. Authenticator Devices
 *
 * After an attestation, you'll need to store three things about the authenticator:
 *
 * - Base64-encoded "Credential ID" (varchar)
 * - Base64-encoded "Public Key" (varchar)
 * - Counter (int)
 *
 * Each authenticator must also be associated to a user so that you can generate a list of
 * authenticator credential IDs to pass into `generateAssertionOptions()`, from which one is
 * expected to generate an assertion response.
 */
const inMemoryUserDeviceDB = {
  [userId]: [
    /**
     * After an attestation, the following authenticator info returned by
     * verifyAttestationResponse() should be persisted somewhere that'll tie it back to the user
     * specified during attestation:
     *
     * {
     *   base64CredentialID: string,
     *   base64PublicKey: string,
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
    rpID,
    randomChallenge,
    userId,
    username,
  ));
});

app.post('/verify-attestation', (req, res) => {
  const { body } = req;

  let verification;
  try {
    verification = verifyAttestationResponse(
      body,
      randomChallenge,
      origin,
    );
  } catch (error) {
    console.error(error);
    return res.status(400).send({ error: error.message });
  }

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

  let verification;
  try {
    verification = verifyAssertionResponse(
      body,
      randomChallenge,
      origin,
      dbAuthenticator,
    );
  } catch (error) {
    console.error(error);
    return res.status(400).send({ error: error.message });
  }

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
