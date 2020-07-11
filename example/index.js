/* eslint-disable @typescript-eslint/no-var-requires */
/**
 * An example Express server showing off a simple integration of @simplewebauthn/server.
 *
 * The webpages served from ./public use @simplewebauthn/browser.
 */
const https = require('https');
const fs = require('fs');

const express = require('express');

const FIDOConformanceRoutes = require('./fido-conformance');

const {
  // Registration ("Attestation")
  generateAttestationOptions,
  verifyAttestationResponse,
  // Login ("Assertion")
  generateAssertionOptions,
  verifyAssertionResponse,
  // Support for FIDO MDS
  // MetadataService,
} = require('@simplewebauthn/server');

/**
 * Initialize MetadataService to enable support for the FIDO Metadata Service (MDS).
 *
 * Metadata enables a greater degree of certainty that the devices interacting with this server are
 * what they claim to be according to their manufacturer.
 *
 * Use of MetadataService is _not_ required to use @simplewebauthn/server. If you do choose to use
 * it, you'll need to set the following environment variables (.env files are supported):
 *
 * ENABLE_MDS=true
 * MDS_API_TOKEN=YourFIDOAccessTokenGoesHere
 *
 * See https://mds2.fidoalliance.org/tokens/ to register for a free access token. When they ask for
 * an Organization Name, "Self" works just fine.
 */
// MetadataService.initialize();

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
 * 2FA and Passwordless WebAuthn flows expect you to be able to uniquely identify the user that
 * performs an attestation or assertion. The user ID you specify here should be your internal,
 * _unique_ ID for that user (uuid, etc...). Avoid using identifying information here, like email
 * addresses, as it may be stored within the authenticator.
 *
 * Here, the example server assumes the following user has completed login:
 */
const loggedInUserId = 'internalUserId';

/**
 * You'll need a database to store a few things:
 *
 * 1. Users
 *
 * You'll need to be able to associate attestation and assertions challenges, and authenticators to
 * a specific user
 *
 * 2. Challenges
 *
 * The totally-random-unique-every-time values you pass into every execution of
 * `generateAttestationOptions()` or `generateAssertionOptions()` MUST be stored until
 * `verifyAttestationResponse()` or `verifyAssertionResponse()` (respectively) is called to verify
 * that the response contains the signed challenge.
 *
 * These values only need to be persisted for `timeout` number of milliseconds (see the `generate`
 * methods and their optional `timeout` parameter)
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
  [loggedInUserId]: {
    id: loggedInUserId,
    username: 'user@yourdomain.com',
    devices: [
      /**
       * {
       *   credentialID: string,
       *   publicKey: string,
       *   counter: number,
       * }
       */
    ],
    /**
     * A simple way of storing a user's current challenge being signed by attestation or assertion.
     * It should be expired after `timeout` milliseconds (optional argument for `generate` methods,
     * defaults to 60000ms)
     */
    currentChallenge: undefined,
  },
};

/**
 * Registration (a.k.a. "Attestation")
 */
app.get('/generate-attestation-options', (req, res) => {
  const user = inMemoryUserDeviceDB[loggedInUserId];

  const {
    /**
     * The username can be a human-readable name, email, etc... as it is intended only for display.
     */
    username,
    devices,
  } = user;

  /**
   * A new, random value needs to be generated every time an attestation is performed!
   * The server needs to temporarily remember this value for verification, so don't lose it until
   * after you verify an authenticator response.
   */
  const challenge = 'totallyUniqueValueEveryAttestation';
  inMemoryUserDeviceDB[loggedInUserId].currentChallenge = challenge;

  res.send(
    generateAttestationOptions({
      serviceName: 'SimpleWebAuthn Example',
      rpID,
      challenge,
      userID: loggedInUserId,
      userName: username,
      timeout: 60000,
      attestationType: 'direct',
      /**
       * Passing in a user's list of already-registered authenticator IDs here prevents users from
       * registering the same device multiple times. The authenticator will simply throw an error in
       * the browser if it's asked to perform an attestation when one of these ID's already resides
       * on it.
       */
      excludedCredentialIDs: devices.map(dev => dev.credentialID),
      /**
       * The optional authenticatorSelection property allows for specifying more constraints around
       * the types of authenticators that users to can use for attestation
       */
      authenticatorSelection: {
        userVerification: 'preferred',
        requireResidentKey: false,
      },
    }),
  );
});

app.post('/verify-attestation', async (req, res) => {
  const { body } = req;

  const user = inMemoryUserDeviceDB[loggedInUserId];

  const expectedChallenge = user.currentChallenge;

  let verification;
  try {
    verification = await verifyAttestationResponse({
      credential: body,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });
  } catch (error) {
    console.error(error);
    return res.status(400).send({ error: error.message });
  }

  const { verified, authenticatorInfo } = verification;

  if (verified) {
    const { base64PublicKey, base64CredentialID, counter } = authenticatorInfo;

    const existingDevice = user.devices.find(device => device.credentialID === base64CredentialID);

    if (!existingDevice) {
      /**
       * Add the returned device to the user's list of devices
       */
      user.devices.push({
        publicKey: base64PublicKey,
        credentialID: base64CredentialID,
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
  const user = inMemoryUserDeviceDB[loggedInUserId];

  /**
   * A new, random value needs to be generated every time an assertion is performed!
   * The server needs to temporarily remember this value for verification, so don't lose it until
   * after you verify an authenticator response.
   */
  const challenge = 'totallyUniqueValueEveryAssertion';
  inMemoryUserDeviceDB[loggedInUserId].currentChallenge = challenge;

  res.send(
    generateAssertionOptions({
      challenge,
      timeout: 60000,
      allowedCredentialIDs: user.devices.map(data => data.credentialID),
      /**
       * This optional value controls whether or not the authenticator needs be able to uniquely
       * identify the user interacting with it (via built-in PIN pad, fingerprint scanner, etc...)
       */
      userVerification: 'preferred',
    }),
  );
});

app.post('/verify-assertion', (req, res) => {
  const { body } = req;

  const user = inMemoryUserDeviceDB[loggedInUserId];

  const expectedChallenge = user.currentChallenge;

  let dbAuthenticator;
  // "Query the DB" here for an authenticator matching `credentialID`
  for (let dev of user.devices) {
    if (dev.credentialID === body.id) {
      dbAuthenticator = dev;
      break;
    }
  }

  if (!dbAuthenticator) {
    throw new Error('could not find authenticator matching', body.id);
  }

  let verification;
  try {
    verification = verifyAssertionResponse({
      credential: body,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator: dbAuthenticator,
    });
  } catch (error) {
    console.error(error);
    return res.status(400).send({ error: error.message });
  }

  const { verified, authenticatorInfo } = verification;

  if (verified) {
    // Update the authenticator's counter in the DB to the newest count in the assertion
    dbAuthenticator.counter = authenticatorInfo.counter;
  }

  res.send({ verified });
});

app.use('/fido', FIDOConformanceRoutes);

https
  .createServer(
    {
      /**
       * You'll need to provide a SSL cert and key here because
       * WebAuthn can only be run from HTTPS:// URLs
       *
       * HINT: If you create a `dev` subdomain A-record that points to 127.0.0.1,
       * you can manually generate an HTTPS certificate for it using Let's Encrypt certbot.
       */
      key: fs.readFileSync('./dev.yourdomain.com.key'),
      cert: fs.readFileSync('./dev.yourdomain.com.crt'),
    },
    app,
  )
  .listen(port, host, () => {
    console.log(`🚀 Server ready at https://${host}:${port}`);
  });
