import fs from 'fs';
import express from 'express';
import fetch from 'node-fetch';

import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  MetadataService,
  MetadataStatement,
  SettingsService,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/types';

import { expectedOrigin, rpID } from './index';
import { LoggedInUser } from './example-server';

interface LoggedInFIDOUser extends LoggedInUser {
  currentAuthenticationUserVerification?: UserVerificationRequirement;
}

/**
 * Create paths specifically for testing with the FIDO Conformance Tools
 */
export const fidoConformanceRouter = express.Router();
export const fidoRouteSuffix = '/fido';

const rpName = 'FIDO Conformance Test';

/**
 * Load JSON metadata statements provided by the Conformance Tools
 *
 * FIDO2 > TESTS CONFIGURATION > DOWNLOAD SERVER METADATA (button)
 */
const statements: MetadataStatement[] = [];

try {
  // Update this to whatever folder you extracted the statements to
  const conformanceMetadataPath = './fido-conformance-mds';
  const conformanceMetadataFilenames = fs.readdirSync(conformanceMetadataPath);
  for (const statementPath of conformanceMetadataFilenames) {
    if (statementPath.endsWith('.json')) {
      const contents = fs.readFileSync(
        `${conformanceMetadataPath}/${statementPath}`,
        'utf-8',
      );
      statements.push(JSON.parse(contents));
    }
  }
} catch (err) {
  // pass
}

/**
 * Initialize MetadataService with Conformance Testing-specific statements.
 *
 * (Grabbed this URL from the POST made on https://mds3.fido.tools/ when you submit your site's URL)
 */
fetch('https://mds3.fido.tools/getEndpoints', {
  method: 'POST',
  body: JSON.stringify({ endpoint: `${expectedOrigin}${fidoRouteSuffix}` }),
  headers: { 'Content-Type': 'application/json' },
})
  .then(resp => resp.json())
  .then(json => {
    const mdsServers: string[] = json.result;

    return MetadataService.initialize({
      statements,
      mdsServers,
      verificationMode: 'strict',
    });
  })
  .catch(console.error)
  .finally(() => {
    console.log('🔐 FIDO Conformance routes ready');
  });

const inMemoryUserDeviceDB: { [username: string]: LoggedInFIDOUser } = {
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
  //   currentAuthenticationUserVerification: undefined,
  // },
};
// A cheap way of remembering who's "logged in" between the request for options and the response
let loggedInUsername: string | undefined = undefined;

/* prettier-ignore */
const supportedAlgorithmIDs = [
  -7,
  -8,
  -35,
  -36,
  -37,
  -38,
  -39,
  -257,
  -258,
  -259,
  -65535,
];

/**
 * [FIDO2] Server Tests > MakeCredential Request
 */
fidoConformanceRouter.post('/attestation/options', async (req, res) => {
  const { body } = req;
  const {
    username,
    displayName,
    authenticatorSelection,
    attestation,
    extensions,
  } = body;

  loggedInUsername = username;

  let user = inMemoryUserDeviceDB[username];
  if (!user) {
    const newUser = {
      id: username,
      username,
      credentials: [],
    };

    inMemoryUserDeviceDB[username] = newUser;
    user = newUser;
  }

  const { credentials } = user;

  const opts = await generateRegistrationOptions({
    rpName,
    rpID,
    userID: username,
    userName: username,
    userDisplayName: displayName,
    attestationType: attestation,
    authenticatorSelection,
    extensions,
    excludeCredentials: credentials.map(cred => ({
      id: cred.id,
      type: 'public-key',
      transports: ['usb', 'ble', 'nfc', 'internal'],
    })),
    supportedAlgorithmIDs,
  });

  req.session.currentChallenge = opts.challenge;

  // Only return the extensions we're given
  opts.extensions = extensions;

  return res.send({
    ...opts,
    status: 'ok',
    errorMessage: '',
  });
});

/**
 * [FIDO2] Server Tests > MakeCredential Response
 */
fidoConformanceRouter.post('/attestation/result', async (req, res) => {
  const body: RegistrationResponseJSON = req.body;

  const user = inMemoryUserDeviceDB[`${loggedInUsername}`];

  const expectedChallenge = req.session.currentChallenge;

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: body,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin,
      supportedAlgorithmIDs,
      requireUserVerification: false,
    });
  } catch (error) {
    const _error: Error = error as Error;
    console.error(`RP - registration: ${_error.message}`);
    return res.status(400).send({ errorMessage: _error.message });
  }

  const { verified, registrationInfo } = verification;

  if (verified && registrationInfo) {
    const { publicKey, id, counter } = registrationInfo.credential;

    const existingDevice = user.credentials.find(cred => cred.id === id);

    if (!existingDevice) {
      /**
       * Add the returned device to the user's list of devices
       */
      user.credentials.push({
        publicKey,
        id,
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
 * [FIDO2] Server Tests > GetAuthentication Request
 */
fidoConformanceRouter.post('/assertion/options', async (req, res) => {
  const { body } = req;
  const { username, userVerification, extensions } = body;

  loggedInUsername = username;

  const user = inMemoryUserDeviceDB[username];

  const { credentials } = user;

  const opts = await generateAuthenticationOptions({
    rpID,
    extensions,
    userVerification,
    allowCredentials: credentials.map(cred => ({
      id: cred.id,
      type: 'public-key',
      transports: ['usb', 'ble', 'nfc', 'internal'],
    })),
  });

  req.session.currentChallenge = opts.challenge;
  user.currentAuthenticationUserVerification = userVerification;

  return res.send({
    ...opts,
    status: 'ok',
    errorMessage: '',
  });
});

fidoConformanceRouter.post('/assertion/result', async (req, res) => {
  const body: AuthenticationResponseJSON = req.body;
  const { id } = body;

  const user = inMemoryUserDeviceDB[`${loggedInUsername}`];

  // Pull up values specified when generation authentication options
  const expectedChallenge = req.session.currentChallenge;
  const userVerification = user.currentAuthenticationUserVerification;

  if (!id) {
    const msg = `Invalid id: ${id}`;
    console.error(`RP - authentication: ${msg}`);
    return res.status(400).send({ errorMessage: msg });
  }

  const existingCredential = user.credentials.find(cred => cred.id === id);

  if (!existingCredential) {
    const msg = `Could not find device matching ${id}`;
    console.error(`RP - authentication: ${msg}`);
    return res.status(400).send({ errorMessage: msg });
  }

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: body,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin,
      expectedRPID: rpID,
      credential: existingCredential,
      advancedFIDOConfig: { userVerification },
      requireUserVerification: false,
    });
  } catch (error) {
    const _error = error as Error;
    console.error(`RP - authentication: ${_error.message}`);
    return res.status(400).send({ errorMessage: _error.message });
  }

  const { verified, authenticationInfo } = verification;

  if (verified) {
    existingCredential.counter = authenticationInfo.newCounter;
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
fidoConformanceRouter.all('*', (req, res, next) => {
  console.log(req.url);
  console.log(req.method);
  console.log(req.body);

  next();
});

/**
 * MDS3ROOT
 *
 * Downloaded from https://mds3.certinfra.fidoalliance.org/
 *
 * Valid until 2045-01-31 @ 00:00 PST
 *
 * SHA256 Fingerprint
 * 66:D9:77:0B:57:71:10:9B:8D:83:55:7B:A2:7D:58:9B:56:BD:B3:BF:DB:DE:A2:D2:42:C4:CA:0D:57:70:A4:7C
 */
export const MDS3ROOT = `-----BEGIN CERTIFICATE-----
MIICaDCCAe6gAwIBAgIPBCqih0DiJLW7+UHXx/o1MAoGCCqGSM49BAMDMGcxCzAJ
BgNVBAYTAlVTMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMScwJQYDVQQLDB5GQUtF
IE1ldGFkYXRhIDMgQkxPQiBST09UIEZBS0UxFzAVBgNVBAMMDkZBS0UgUm9vdCBG
QUtFMB4XDTE3MDIwMTAwMDAwMFoXDTQ1MDEzMTIzNTk1OVowZzELMAkGA1UEBhMC
VVMxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxJzAlBgNVBAsMHkZBS0UgTWV0YWRh
dGEgMyBCTE9CIFJPT1QgRkFLRTEXMBUGA1UEAwwORkFLRSBSb290IEZBS0UwdjAQ
BgcqhkjOPQIBBgUrgQQAIgNiAASKYiz3YltC6+lmxhPKwA1WFZlIqnX8yL5RybSL
TKFAPEQeTD9O6mOz+tg8wcSdnVxHzwnXiQKJwhrav70rKc2ierQi/4QUrdsPes8T
EirZOkCVJurpDFbXZOgs++pa4XmjYDBeMAsGA1UdDwQEAwIBBjAPBgNVHRMBAf8E
BTADAQH/MB0GA1UdDgQWBBQGcfeCs0Y8D+lh6U5B2xSrR74eHTAfBgNVHSMEGDAW
gBQGcfeCs0Y8D+lh6U5B2xSrR74eHTAKBggqhkjOPQQDAwNoADBlAjEA/xFsgri0
xubSa3y3v5ormpPqCwfqn9s0MLBAtzCIgxQ/zkzPKctkiwoPtDzI51KnAjAmeMyg
X2S5Ht8+e+EQnezLJBJXtnkRWY+Zt491wgt/AwSs5PHHMv5QgjELOuMxQBc=
-----END CERTIFICATE-----
`;

// Set above root cert for use by MetadataService
SettingsService.setRootCertificates({
  identifier: 'mds',
  certificates: [MDS3ROOT],
});
// Reset preset root certificates
SettingsService.setRootCertificates({ identifier: 'apple', certificates: [] });
SettingsService.setRootCertificates({
  identifier: 'android-key',
  certificates: [],
});
SettingsService.setRootCertificates({
  identifier: 'android-safetynet',
  certificates: [],
});
