/* eslint-disable @typescript-eslint/no-var-requires */
const express = require('express');
const { v4: uuidv4 } = require('uuid');

const {
  generateAttestationOptions,
  verifyAttestationResponse,
  generateAssertionOptions,
  verifyAssertionResponse,
} = require('@simplewebauthn/server');

const inMemoryUserDeviceDB = {
  // [username]: string: {
  //   id: loggedInUserId,
  //   username: 'user@yourdomain.com',
  //   devices: [
  //     /**
  //      * {
  //      *   credentialID: string,
  //      *   publicKey: string,
  //      *   counter: number,
  //      * }
  //      */
  //   ],
  //   currentChallenge: undefined,
  // },
};

/**
 * Create paths specifically for testing with the FIDO Conformance Tools
 */
const fidoComplianceRouter = express.Router();

let loggedInUsername = undefined;
const serviceName = 'FIDO Conformance Test';
const rpID = 'dev.dontneeda.pw';
const origin = 'https://dev.dontneeda.pw';

/**
 * [FIDO2] Server Tests > MakeCredential Request
 */
fidoComplianceRouter.post('/attestation/options', (req, res) => {
  const { body } = req;
  const { username, displayName, authenticatorSelection, attestation, extensions } = body;

  loggedInUsername = username;

  let user = inMemoryUserDeviceDB[username];
  if (!user) {
    const newUser = {
      id: username,
      username,
      devices: [],
    };

    inMemoryUserDeviceDB[username] = newUser;
    user = newUser;
  }

  const { devices } = user;

  const challenge = uuidv4();
  user.currentChallenge = challenge;

  const opts = generateAttestationOptions({
    serviceName,
    rpID,
    challenge,
    userID: username,
    userName: username,
    userDisplayName: displayName,
    attestationType: attestation,
    authenticatorSelection,
    extensions,
    excludedCredentialIDs: devices.map(dev => dev.credentialID),
  });

  return res.send({
    ...opts,
    status: 'ok',
    errorMessage: '',
  });
});

/**
 * [FIDO2] Server Tests > MakeCredential Response
 */
fidoComplianceRouter.post('/attestation/result', (req, res) => {
  const { body } = req;

  const user = inMemoryUserDeviceDB[loggedInUsername];

  const expectedChallenge = user.currentChallenge;

  let verification;
  try {
    verification = verifyAttestationResponse({
      credential: body,
      expectedChallenge: Buffer.from(expectedChallenge, 'base64'),
      expectedOrigin: origin,
    });
  } catch (error) {
    console.error(error.message);
    return res.status(400).send({ errorMessage: error.message });
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

  return res.send({
    status: verified ? 'ok' : '',
    errorMessage: '',
  });
});

/**
 * [FIDO2] Server Tests > GetAssertion Request
 */
fidoComplianceRouter.post('/assertion/options', (req, res) => {
  const { body } = req;
  const { username, userVerification, extensions } = body;

  loggedInUsername = username;

  let user = inMemoryUserDeviceDB[username];

  const { devices } = user;

  const challenge = uuidv4();
  user.currentChallenge = challenge;

  const opts = generateAssertionOptions({
    challenge,
    extensions,
    userVerification,
    allowedCredentialIDs: devices.map(dev => dev.credentialID),
  });

  return res.send({
    ...opts,
    status: 'ok',
    errorMessage: '',
  });
});

fidoComplianceRouter.post('/assertion/result', (req, res) => {
  const { body } = req;
  const { id } = body;

  const user = inMemoryUserDeviceDB[loggedInUsername];
  const expectedChallenge = user.currentChallenge;
  const existingDevice = user.devices.find(device => device.credentialID === id);

  if (!existingDevice) {
    throw new Error('Assertion device is not registered to user');
  }

  let verification;
  try {
    verification = verifyAssertionResponse({
      credential: body,
      expectedChallenge: Buffer.from(expectedChallenge, 'base64'),
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator: existingDevice,
    });
  } catch (error) {
    console.error(error.message);
    return res.status(400).send({ errorMessage: error.message });
  }

  const { verified, authenticatorInfo } = verification;

  if (verified) {
    const { base64CredentialID, counter } = authenticatorInfo;
    const existingDevice = user.devices.find(device => device.credentialID === base64CredentialID);
    existingDevice.counter = counter;
  }

  return res.send({
    status: verified ? 'ok' : '',
    errorMessage: '',
  });
});

fidoComplianceRouter.all('*', (req, res, next) => {
  console.log(req.url);
  console.log(req.method);
  console.log(req.body);

  next();
});

module.exports = fidoComplianceRouter;
