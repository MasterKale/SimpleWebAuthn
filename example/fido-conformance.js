/* eslint-disable @typescript-eslint/no-var-requires */
const fs = require('fs');
const express = require('express');
const { v4: uuidv4 } = require('uuid');

require('dotenv').config();

const {
  generateAttestationOptions,
  verifyAttestationResponse,
  generateAssertionOptions,
  verifyAssertionResponse,
  MetadataService,
} = require('@simplewebauthn/server');

const serviceName = 'FIDO Conformance Test';
const rpID = 'localhost';
const origin = 'https://localhost';

/**
 * Load JSON metadata statements provided by the Conformance Tools
 *
 * FIDO2 > TESTS CONFIGURATION > DOWNLOAD SERVER METADATA (button)
 */
// Update this to whatever folder you extracted the statements to
const statements = [];

try {
  const conformanceMetadataPath = './fido-conformance-mds-v1.3.4';
  const conformanceMetadataFilenames = fs.readdirSync(conformanceMetadataPath);
  for (const statementPath of conformanceMetadataFilenames) {
    if (statementPath.endsWith('.json')) {
      const contents = fs.readFileSync(`${conformanceMetadataPath}/${statementPath}`, 'utf-8');
      statements.push(JSON.parse(contents));
    }
  }
  console.log('initializing metadata service with', conformanceMetadataFilenames);
} catch (err) {
  // pass
}
/**
 * Initialize MetadataService to enable support for the FIDO Metadata Service (MDS).
 *
 * Metadata enables a greater degree of certainty that the devices interacting with this server are
 * what they claim to be according to their manufacturer.
 *
 * Use of MetadataService is _not_ required to use @simplewebauthn/server. If you do choose to use
 * it, you'll need to provide at least one MDS endpoint
 *
 * See https://mds2.fidoalliance.org/tokens/ to register for a free access token. When they ask for
 * an Organization Name, "Self" works just fine.
 */
const mdsAPIToken = process.env.MDS_API_TOKEN;
MetadataService.initialize({
  statements,
  mdsServers: [
    {
      url: `https://mds2.fidoalliance.org/?token=${mdsAPIToken}`,
      rootCertURL: 'https://mds.fidoalliance.org/Root.cer',
      metadataURLSuffix: `?token=${mdsAPIToken}`,
    },
  ],
});

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
  //   currentAssertionUserVerification: undefined,
  // },
};

/**
 * Create paths specifically for testing with the FIDO Conformance Tools
 */
const fidoComplianceRouter = express.Router();

let loggedInUsername = undefined;

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
fidoComplianceRouter.post('/attestation/result', async (req, res) => {
  const { body } = req;

  const user = inMemoryUserDeviceDB[loggedInUsername];

  const expectedChallenge = user.currentChallenge;

  let verification;
  try {
    verification = await verifyAttestationResponse({
      credential: body,
      expectedChallenge: Buffer.from(expectedChallenge, 'base64'),
      expectedOrigin: origin,
    });
  } catch (error) {
    console.error(`RP - attestation: ${error.message}`);
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
  user.currentAssertionUserVerification = userVerification;

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

  // Pull up values specified when generation assertion options
  const expectedChallenge = user.currentChallenge;
  const userVerification = user.currentAssertionUserVerification;

  const existingDevice = user.devices.find(device => device.credentialID === id);

  let verification;
  try {
    verification = verifyAssertionResponse({
      credential: body,
      expectedChallenge: Buffer.from(expectedChallenge, 'base64'),
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator: existingDevice,
      fidoUserVerification: userVerification,
    });
  } catch (error) {
    console.error(`RP - assertion: ${error.message}`);
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

/**
 * A catch-all for future test routes we might need to support but haven't yet defined (helps with
 * discovering which routes, what methods, and what data need to be defined)
 */
fidoComplianceRouter.all('*', (req, res, next) => {
  console.log(req.url);
  console.log(req.method);
  console.log(req.body);

  next();
});

module.exports = fidoComplianceRouter;
