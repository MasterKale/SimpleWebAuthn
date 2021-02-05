jest.mock('../helpers/generateChallenge');

import generateAttestationOptions from './generateAttestationOptions';

test('should generate credential request options suitable for sending via JSON', () => {
  const rpName = 'SimpleWebAuthn';
  const rpID = 'not.real';
  const challenge = 'totallyrandomvalue';
  const userID = '1234';
  const userName = 'usernameHere';
  const timeout = 1;
  const attestationType = 'indirect';

  const options = generateAttestationOptions({
    rpName,
    rpID,
    challenge,
    userID,
    userName,
    timeout,
    attestationType,
  });

  expect(options).toEqual({
    // Challenge, base64url-encoded
    challenge: 'dG90YWxseXJhbmRvbXZhbHVl',
    rp: {
      name: rpName,
      id: rpID,
    },
    user: {
      id: userID,
      name: userName,
      displayName: userName,
    },
    pubKeyCredParams: [
      { alg: -7, type: 'public-key' },
      { alg: -8, type: 'public-key' },
      { alg: -36, type: 'public-key' },
      { alg: -37, type: 'public-key' },
      { alg: -38, type: 'public-key' },
      { alg: -39, type: 'public-key' },
      { alg: -257, type: 'public-key' },
      { alg: -258, type: 'public-key' },
      { alg: -259, type: 'public-key' },
    ],
    timeout,
    attestation: attestationType,
    excludeCredentials: [],
    authenticatorSelection: {
      requireResidentKey: false,
      userVerification: 'preferred',
    },
  });
});

test('should map excluded credential IDs if specified', () => {
  const options = generateAttestationOptions({
    rpName: 'SimpleWebAuthn',
    rpID: 'not.real',
    challenge: 'totallyrandomvalue',
    userID: '1234',
    userName: 'usernameHere',
    excludeCredentials: [
      {
        id: Buffer.from('someIDhere', 'ascii'),
        type: 'public-key',
        transports: ['usb', 'ble', 'nfc', 'internal'],
      },
    ],
  });

  expect(options.excludeCredentials).toEqual([
    {
      id: 'c29tZUlEaGVyZQ',
      type: 'public-key',
      transports: ['usb', 'ble', 'nfc', 'internal'],
    },
  ]);
});

test('defaults to 60 seconds if no timeout is specified', () => {
  const options = generateAttestationOptions({
    rpName: 'SimpleWebAuthn',
    rpID: 'not.real',
    challenge: 'totallyrandomvalue',
    userID: '1234',
    userName: 'usernameHere',
  });

  expect(options.timeout).toEqual(60000);
});

test('defaults to none attestation if no attestation type is specified', () => {
  const options = generateAttestationOptions({
    rpName: 'SimpleWebAuthn',
    rpID: 'not.real',
    challenge: 'totallyrandomvalue',
    userID: '1234',
    userName: 'usernameHere',
  });

  expect(options.attestation).toEqual('none');
});

test('should set authenticatorSelection if specified', () => {
  const options = generateAttestationOptions({
    rpName: 'SimpleWebAuthn',
    rpID: 'not.real',
    challenge: 'totallyrandomvalue',
    userID: '1234',
    userName: 'usernameHere',
    authenticatorSelection: {
      authenticatorAttachment: 'cross-platform',
      requireResidentKey: false,
      userVerification: 'preferred',
    },
  });

  expect(options.authenticatorSelection).toEqual({
    authenticatorAttachment: 'cross-platform',
    requireResidentKey: false,
    userVerification: 'preferred',
  });
});

test('should set extensions if specified', () => {
  const options = generateAttestationOptions({
    rpName: 'SimpleWebAuthn',
    rpID: 'not.real',
    challenge: 'totallyrandomvalue',
    userID: '1234',
    userName: 'usernameHere',
    extensions: { appid: 'simplewebauthn' },
  });

  expect(options.extensions).toEqual({
    appid: 'simplewebauthn',
  });
});

test('should generate a challenge if one is not provided', () => {
  const options = generateAttestationOptions({
    rpID: 'not.real',
    rpName: 'SimpleWebAuthn',
    userID: '1234',
    userName: 'usernameHere',
  });

  // base64url-encoded 16-byte buffer from mocked `generateChallenge()`
  expect(options.challenge).toEqual('AQIDBAUGBwgJCgsMDQ4PEA');
});

test('should use custom supported algorithm IDs as-is when provided', () => {
  const options = generateAttestationOptions({
    rpID: 'not.real',
    rpName: 'SimpleWebAuthn',
    userID: '1234',
    userName: 'usernameHere',
    supportedAlgorithmIDs: [-7, -8, -65535],
  });

  expect(options.pubKeyCredParams).toEqual([
    { alg: -7, type: 'public-key' },
    { alg: -8, type: 'public-key' },
    { alg: -65535, type: 'public-key' },
  ]);
});
