/* eslint-disable @typescript-eslint/no-var-requires */
const fs = require('fs');
const express = require('express');
const { v4: uuidv4 } = require('uuid');

const {
  generateAttestationOptions,
  verifyAttestationResponse,
  generateAssertionOptions,
  verifyAssertionResponse,
  MetadataService,
} = require('@simplewebauthn/server');

/**
 * Load JSON metadata statements provided by the Conformance Tools
 *
 * FIDO2 > TESTS CONFIGURATION > DOWNLOAD SERVER METADATA (button)
 */
// Update this to whatever folder you extracted the statements to
const conformanceMetadataPath = './fido-conformance-mds-v1.3.4';
const conformanceMetadataFilenames = fs.readdirSync(conformanceMetadataPath);
const statements = [];
for (const statementPath of conformanceMetadataFilenames) {
  if (statementPath.endsWith('.json')) {
    const contents = fs.readFileSync(`${conformanceMetadataPath}/${statementPath}`, 'utf-8');
    statements.push(JSON.parse(contents));
  }
}
// Initialize the metadata service with the prepared statements
// For MakeCredential and GetAssertion Request/Response tests
console.log('initializing metadata service with', conformanceMetadataFilenames);
MetadataService.initialize({
  statements,
  mdsServers: [
    {
      url:
        'https://fidoalliance.co.nz/mds//execute/5abc7da5609b63e58c44144bc7a6bc9a2cc27ee520fb35dd03fcad36146d1a8e',
      rootCertURL: 'https://fidoalliance.co.nz/mds/pki/MDSROOT.crt',
      metadataURLSuffix: '',
    },
    {
      url:
        'https://fidoalliance.co.nz/mds//execute/6382ec8aee2d9c31d4ab3a1d01bd87796346e09d772ea0808e8602c70940caad',
      rootCertURL: 'https://fidoalliance.co.nz/mds/pki/MDSROOT.crt',
      metadataURLSuffix: '',
    },
    {
      url:
        'https://fidoalliance.co.nz/mds//execute/82764926806f16480a1dd607428e789395d3453d7dc71d5914f44b6f2af56c1a',
      rootCertURL: 'https://fidoalliance.co.nz/mds/pki/MDSROOT.crt',
      metadataURLSuffix: '',
    },
    {
      url:
        'https://fidoalliance.co.nz/mds//execute/9bb53a0c09e8d8abc1760498df17c3111545a5376296985cfc613c611e90757a',
      rootCertURL: 'https://fidoalliance.co.nz/mds/pki/MDSROOT.crt',
      metadataURLSuffix: '',
    },
    {
      url:
        'https://fidoalliance.co.nz/mds//execute/d6dba4496be1a76148bc88799425bb23e01183ef0149b85042462650e94a9a62',
      rootCertURL: 'https://fidoalliance.co.nz/mds/pki/MDSROOT.crt',
      metadataURLSuffix: '',
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
