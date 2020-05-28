/* eslint-disable @typescript-eslint/no-var-requires */
const express = require('express');
const { v4: uuidv4 } = require('uuid');

const {
  generateAttestationOptions,
  verifyAttestationResponse,
} = require('@simplewebauthn/server');

/**
 * Create paths specifically for testing with the FIDO Conformance Tools
 */
const fidoComplianceRouter = express.Router();

/**
 * [FIDO2] Server Tests > MakeCredential Request
 */
fidoComplianceRouter.post('/attestation/options', (req, res) => {
  const { body } = req;
  const { username, displayName, authenticatorSelection, attestation, extensions } = body;

  console.log('hello1');
  console.log(body);

  const opts = generateAttestationOptions({
    serviceName: 'FIDO Conformance Test',
    rpID: 'fido-compliance-test',
    challenge: Buffer.from(uuidv4(), 'ascii').toString('base64'),
    userID: username,
    userName: username,
    userDisplayName: displayName,
    attestationType: attestation,
    authenticatorSelection,
    extensions,
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
  const { response } = body;

  console.log('hello2');
  console.log(body);
  // const verified = verifyAttestationResponse(
  //   {
  //     base64AttestationObject: response.attestationObject,
  //     base64ClientDataJSON: response.clientDataJSON,
  //   },
  // );

  // console.log(verified);

  return res.send({
    status: 'ok',
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
