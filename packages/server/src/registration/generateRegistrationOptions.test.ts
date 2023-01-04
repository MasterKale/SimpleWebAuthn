jest.mock('../helpers/generateChallenge');

import { generateRegistrationOptions } from './generateRegistrationOptions';

test('should generate credential request options suitable for sending via JSON', () => {
  const rpName = 'SimpleWebAuthn';
  const rpID = 'not.real';
  const challenge = 'totallyrandomvalue';
  const userID = '1234';
  const userName = 'usernameHere';
  const timeout = 1;
  const attestationType = 'indirect';

  const options = generateRegistrationOptions({
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
      { alg: -8, type: 'public-key' },
      { alg: -7, type: 'public-key' },
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
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
    extensions: {
      credProps: true,
    }
  });
});

test('should map excluded credential IDs if specified', () => {
  const options = generateRegistrationOptions({
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
  const options = generateRegistrationOptions({
    rpName: 'SimpleWebAuthn',
    rpID: 'not.real',
    challenge: 'totallyrandomvalue',
    userID: '1234',
    userName: 'usernameHere',
  });

  expect(options.timeout).toEqual(60000);
});

test('defaults to none attestation if no attestation type is specified', () => {
  const options = generateRegistrationOptions({
    rpName: 'SimpleWebAuthn',
    rpID: 'not.real',
    challenge: 'totallyrandomvalue',
    userID: '1234',
    userName: 'usernameHere',
  });

  expect(options.attestation).toEqual('none');
});

test('should set authenticatorSelection if specified', () => {
  const options = generateRegistrationOptions({
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
  const options = generateRegistrationOptions({
    rpName: 'SimpleWebAuthn',
    rpID: 'not.real',
    challenge: 'totallyrandomvalue',
    userID: '1234',
    userName: 'usernameHere',
    extensions: { appid: 'simplewebauthn' },
  });

  expect(options.extensions?.appid).toEqual('simplewebauthn');
});

test('should include credProps if extensions are not provided', () => {
  const options = generateRegistrationOptions({
    rpName: 'SimpleWebAuthn',
    rpID: 'not.real',
    userID: '1234',
    userName: 'usernameHere',
  });

  expect(options.extensions?.credProps).toEqual(true);
});

test('should include credProps if extensions are provided', () => {
  const options = generateRegistrationOptions({
    rpName: 'SimpleWebAuthn',
    rpID: 'not.real',
    userID: '1234',
    userName: 'usernameHere',
    extensions: { appid: 'simplewebauthn' },
  });

  expect(options.extensions?.credProps).toEqual(true);
});

test('should generate a challenge if one is not provided', () => {
  const options = generateRegistrationOptions({
    rpID: 'not.real',
    rpName: 'SimpleWebAuthn',
    userID: '1234',
    userName: 'usernameHere',
  });

  // base64url-encoded 16-byte buffer from mocked `generateChallenge()`
  expect(options.challenge).toEqual('AQIDBAUGBwgJCgsMDQ4PEA');
});

test('should use custom supported algorithm IDs as-is when provided', () => {
  const options = generateRegistrationOptions({
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

test('should require resident key if residentKey option is absent but requireResidentKey is set to true', () => {
  const options = generateRegistrationOptions({
    rpID: 'not.real',
    rpName: 'SimpleWebAuthn',
    userID: '1234',
    userName: 'usernameHere',
    authenticatorSelection: {
      requireResidentKey: true,
    },
  });

  expect(options.authenticatorSelection?.requireResidentKey).toEqual(true);
  expect(options.authenticatorSelection?.residentKey).toEqual('required');
});

test('should discourage resident key if residentKey option is absent but requireResidentKey is set to false', () => {
  const options = generateRegistrationOptions({
    rpID: 'not.real',
    rpName: 'SimpleWebAuthn',
    userID: '1234',
    userName: 'usernameHere',
    authenticatorSelection: {
      requireResidentKey: false,
    },
  });

  expect(options.authenticatorSelection?.requireResidentKey).toEqual(false);
  expect(options.authenticatorSelection?.residentKey).toBeUndefined();
});

test('should prefer resident key if both residentKey and requireResidentKey options are absent', () => {
  const options = generateRegistrationOptions({
    rpID: 'not.real',
    rpName: 'SimpleWebAuthn',
    userID: '1234',
    userName: 'usernameHere',
  });

  expect(options.authenticatorSelection?.requireResidentKey).toEqual(false);
  expect(options.authenticatorSelection?.residentKey).toEqual('preferred');
});

test('should set requireResidentKey to true if residentKey if set to required', () => {
  const options = generateRegistrationOptions({
    rpID: 'not.real',
    rpName: 'SimpleWebAuthn',
    userID: '1234',
    userName: 'usernameHere',
    authenticatorSelection: {
      residentKey: 'required',
    },
  });

  expect(options.authenticatorSelection?.requireResidentKey).toEqual(true);
  expect(options.authenticatorSelection?.residentKey).toEqual('required');
});

test('should set requireResidentKey to false if residentKey if set to preferred', () => {
  const options = generateRegistrationOptions({
    rpID: 'not.real',
    rpName: 'SimpleWebAuthn',
    userID: '1234',
    userName: 'usernameHere',
    authenticatorSelection: {
      residentKey: 'preferred',
    },
  });

  expect(options.authenticatorSelection?.requireResidentKey).toEqual(false);
  expect(options.authenticatorSelection?.residentKey).toEqual('preferred');
});

test('should set requireResidentKey to false if residentKey if set to discouraged', () => {
  const options = generateRegistrationOptions({
    rpID: 'not.real',
    rpName: 'SimpleWebAuthn',
    userID: '1234',
    userName: 'usernameHere',
    authenticatorSelection: {
      residentKey: 'discouraged',
    },
  });

  expect(options.authenticatorSelection?.requireResidentKey).toEqual(false);
  expect(options.authenticatorSelection?.residentKey).toEqual('discouraged');
});

test('should prefer Ed25519 in pubKeyCredParams', () => {
  const options = generateRegistrationOptions({
    rpName: 'SimpleWebAuthn',
    rpID: 'not.real',
    challenge: 'totallyrandomvalue',
    userID: '1234',
    userName: 'usernameHere',
  });

  expect(options.pubKeyCredParams[0].alg).toEqual(-8);
});
