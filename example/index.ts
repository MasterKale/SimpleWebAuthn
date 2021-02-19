/* eslint-disable @typescript-eslint/no-var-requires */
/**
 * An example Express server showing off a simple integration of @simplewebauthn/server.
 *
 * The webpages served from ./public use @simplewebauthn/browser.
 */

import https from 'https';
import fs from 'fs';

import express from 'express';
import dotenv from 'dotenv';
import base64url from 'base64url';

dotenv.config();

import {
  // Registration ("Attestation")
  generateAttestationOptions,
  verifyAttestationResponse,
  // Login ("Assertion")
  generateAssertionOptions,
  GenerateAttestationOptionsOpts,
  verifyAssertionResponse,
  VerifyAttestationResponseOpts,
  VerifiedAttestation,
} from '@simplewebauthn/server';

import type {
  AttestationCredentialJSON,
  AssertionCredentialJSON,
  AuthenticatorDevice,
  PublicKeyCredentialCreationOptionsJSON,
} from '@simplewebauthn/typescript-types';

import { LoggedInUser } from './example-server';

const app = express();
const host = '0.0.0.0';
const port = 443;

const { ENABLE_CONFORMANCE } = process.env;

app.use(express.static('./public/'));
app.use(express.json());

/**
 * If the words "metadata statements" mean anything to you, you'll want to enable this route. It
 * contains an example of a more complex deployment of SimpleWebAuthn with support enabled for the
 * FIDO Metadata Service. This enables greater control over the types of authenticators that can
 * interact with the Rely Party (a.k.a. "RP", a.k.a. "this server").
 */
if (ENABLE_CONFORMANCE === 'true') {
  import('./fido-conformance').then(({ fidoRouteSuffix, fidoConformanceRouter }) => {
    app.use(fidoRouteSuffix, fidoConformanceRouter);
  });
}

/**
 * RP ID represents the "scope" of websites on which a authenticator should be usable. The Origin
 * represents the expected URL from which an attestation or assertion occurs.
 */
const rpID = 'localhost';
const expectedOrigin = `https://${rpID}`;
/**
 * 2FA and Passwordless WebAuthn flows expect you to be able to uniquely identify the user that
 * performs an attestation or assertion. The user ID you specify here should be your internal,
 * _unique_ ID for that user (uuid, etc...). Avoid using identifying information here, like email
 * addresses, as it may be stored within the authenticator.
 *
 * Here, the example server assumes the following user has completed login:
 */
const loggedInUserId = 'internalUserId';

const inMemoryUserDeviceDB: { [loggedInUserId: string]: LoggedInUser } = {
  [loggedInUserId]: {
    id: loggedInUserId,
    username: `user@${rpID}`,
    devices: [],
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
  const generateAttestationOptionsOpts: GenerateAttestationOptionsOpts = {
    rpName: 'SimpleWebAuthn Example',
    rpID,
    userID: loggedInUserId,
    userName: username,
    timeout: 60000,
    attestationType: 'indirect',
    /**
     * Passing in a user's list of already-registered authenticator IDs here prevents users from
     * registering the same device multiple times. The authenticator will simply throw an error in
     * the browser if it's asked to perform an attestation when one of these ID's already resides
     * on it.
     */
    excludeCredentials: devices.map(dev => ({
      id: dev.credentialID,
      type: 'public-key',
      transports: ['usb', 'ble', 'nfc', 'internal'],
    })),
    /**
     * The optional authenticatorSelection property allows for specifying more constraints around
     * the types of authenticators that users to can use for attestation
     */
    authenticatorSelection: {
      userVerification: 'preferred',
      requireResidentKey: false,
    },
  };
  const options: PublicKeyCredentialCreationOptionsJSON = generateAttestationOptions(generateAttestationOptionsOpts);

  /**
   * The server needs to temporarily remember this value for verification, so don't lose it until
   * after you verify an authenticator response.
   */
  inMemoryUserDeviceDB[loggedInUserId].currentChallenge = options.challenge;

  res.send(options);
});

app.post('/verify-attestation', async (req, res) => {
  const body: AttestationCredentialJSON = req.body;

  const user = inMemoryUserDeviceDB[loggedInUserId];

  const expectedChallenge = user.currentChallenge;
  const verifyAttestationResponseOptions: VerifyAttestationResponseOpts = {
    credential: body,
    expectedChallenge: `${expectedChallenge}`,
    expectedOrigin,
    expectedRPID: rpID,
  };
  let verification: VerifiedAttestation;
  try {
    verification = await verifyAttestationResponse(verifyAttestationResponseOptions);
  } catch (error) {
    console.error(error);
    return res.status(400).send({ error: error.message });
  }

  const { verified, attestationInfo } = verification;

  if (verified && attestationInfo) {
    const { credentialPublicKey, credentialID, counter } = attestationInfo;

    const existingDevice = user.devices.find(device => device.credentialID === credentialID);

    if (!existingDevice) {
      /**
       * Add the returned device to the user's list of devices
       */
      const newDevice: AuthenticatorDevice = {
        credentialPublicKey,
        credentialID,
        counter,
      };
      user.devices.push(newDevice);
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

  const options = generateAssertionOptions({
    timeout: 60000,
    allowCredentials: user.devices.map(dev => ({
      id: dev.credentialID,
      type: 'public-key',
      transports: ['usb', 'ble', 'nfc', 'internal'],
    })),
    /**
     * This optional value controls whether or not the authenticator needs be able to uniquely
     * identify the user interacting with it (via built-in PIN pad, fingerprint scanner, etc...)
     */
    userVerification: 'preferred',
    rpID,
  });

  /**
   * The server needs to temporarily remember this value for verification, so don't lose it until
   * after you verify an authenticator response.
   */
  inMemoryUserDeviceDB[loggedInUserId].currentChallenge = options.challenge;

  res.send(options);
});

app.post('/verify-assertion', (req, res) => {
  const body: AssertionCredentialJSON = req.body;

  const user = inMemoryUserDeviceDB[loggedInUserId];

  const expectedChallenge = user.currentChallenge;

  let dbAuthenticator;
  const bodyCredIDBuffer = base64url.toBuffer(body.rawId);
  // "Query the DB" here for an authenticator matching `credentialID`
  for (const dev of user.devices) {
    if (dev.credentialID.equals(bodyCredIDBuffer)) {
      dbAuthenticator = dev;
      break;
    }
  }

  if (!dbAuthenticator) {
    throw new Error(`could not find authenticator matching ${body.id}`);
  }

  let verification: VerifyAssertionResponseOpts;
  try {
    verification = verifyAssertionResponse({
      credential: body,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin,
      expectedRPID: rpID,
      authenticator: dbAuthenticator,
    });
  } catch (error) {
    console.error(error);
    return res.status(400).send({ error: error.message });
  }

  const { verified, assertionInfo } = verification;

  if (verified) {
    // Update the authenticator's counter in the DB to the newest count in the assertion
    dbAuthenticator.counter = assertionInfo.newCounter;
  }

  res.send({ verified });
});

https
  .createServer(
    {
      /**
       * WebAuthn can only be run from https:// URLs. See the README on how to generate this SSL cert and key pair using mkcert
       */
      key: fs.readFileSync(`./${rpID}.key`),
      cert: fs.readFileSync(`./${rpID}.crt`),
    },
    app,
  )
  .listen(port, host, () => {
    console.log(`🚀 Server ready at https://${rpID} (${host}:${port})`);
  });
