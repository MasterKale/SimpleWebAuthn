import { assertEquals } from 'https://deno.land/std@0.198.0/assert/mod.ts';
import { returnsNext, stub } from 'https://deno.land/std@0.198.0/testing/mock.ts';

import { generateRegistrationOptions } from './generateRegistrationOptions.ts';
import { _generateChallengeInternals } from '../helpers/generateChallenge.ts';
import { isoUint8Array } from '../helpers/iso/index.ts';

Deno.test('should generate credential request options suitable for sending via JSON', async () => {
  const rpName = 'SimpleWebAuthn';
  const rpID = 'not.real';
  const challenge = 'totallyrandomvalue';
  const userID = '1234';
  const userName = 'usernameHere';
  const timeout = 1;
  const attestationType = 'indirect';

  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    challenge,
    userID,
    userName,
    timeout,
    attestationType,
  });

  assertEquals(
    options,
    {
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
        { alg: -257, type: 'public-key' },
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
      },
    },
  );
});

Deno.test('should map excluded credential IDs if specified', async () => {
  const options = await generateRegistrationOptions({
    rpName: 'SimpleWebAuthn',
    rpID: 'not.real',
    challenge: 'totallyrandomvalue',
    userID: '1234',
    userName: 'usernameHere',
    excludeCredentials: [
      {
        id: isoUint8Array.fromASCIIString('someIDhere'),
        type: 'public-key',
        transports: ['usb', 'ble', 'nfc', 'internal'],
      },
    ],
  });

  assertEquals(
    options.excludeCredentials,
    [
      {
        id: 'c29tZUlEaGVyZQ',
        type: 'public-key',
        transports: ['usb', 'ble', 'nfc', 'internal'],
      },
    ],
  );
});

Deno.test('defaults to 60 seconds if no timeout is specified', async () => {
  const options = await generateRegistrationOptions({
    rpName: 'SimpleWebAuthn',
    rpID: 'not.real',
    challenge: 'totallyrandomvalue',
    userID: '1234',
    userName: 'usernameHere',
  });

  assertEquals(options.timeout, 60000);
});

Deno.test('defaults to none attestation if no attestation type is specified', async () => {
  const options = await generateRegistrationOptions({
    rpName: 'SimpleWebAuthn',
    rpID: 'not.real',
    challenge: 'totallyrandomvalue',
    userID: '1234',
    userName: 'usernameHere',
  });

  assertEquals(options.attestation, 'none');
});

Deno.test('should set authenticatorSelection if specified', async () => {
  const options = await generateRegistrationOptions({
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

  assertEquals(
    options.authenticatorSelection,
    {
      authenticatorAttachment: 'cross-platform',
      requireResidentKey: false,
      userVerification: 'preferred',
    },
  );
});

Deno.test('should set extensions if specified', async () => {
  const options = await generateRegistrationOptions({
    rpName: 'SimpleWebAuthn',
    rpID: 'not.real',
    challenge: 'totallyrandomvalue',
    userID: '1234',
    userName: 'usernameHere',
    extensions: { appid: 'simplewebauthn' },
  });

  assertEquals(options.extensions?.appid, 'simplewebauthn');
});

Deno.test('should include credProps if extensions are not provided', async () => {
  const options = await generateRegistrationOptions({
    rpName: 'SimpleWebAuthn',
    rpID: 'not.real',
    userID: '1234',
    userName: 'usernameHere',
  });

  assertEquals(options.extensions?.credProps, true);
});

Deno.test('should include credProps if extensions are provided', async () => {
  const options = await generateRegistrationOptions({
    rpName: 'SimpleWebAuthn',
    rpID: 'not.real',
    userID: '1234',
    userName: 'usernameHere',
    extensions: { appid: 'simplewebauthn' },
  });

  assertEquals(options.extensions?.credProps, true);
});

Deno.test('should generate a challenge if one is not provided', async () => {
  const mockGenerateChallenge = stub(
    _generateChallengeInternals,
    'stubThis',
    returnsNext([
      new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
    ]),
  );

  const options = await generateRegistrationOptions({
    rpID: 'not.real',
    rpName: 'SimpleWebAuthn',
    userID: '1234',
    userName: 'usernameHere',
  });

  // base64url-encoded 16-byte buffer from mocked `generateChallenge()`
  assertEquals(options.challenge, 'AQIDBAUGBwgJCgsMDQ4PEA');

  mockGenerateChallenge.restore();
});

Deno.test('should treat string challenges as UTF-8 strings', async () => {
  const options = await generateRegistrationOptions({
    rpID: 'not.real',
    rpName: 'SimpleWebAuthn',
    userID: '1234',
    userName: 'usernameHere',
    challenge: 'こんにちは',
  });

  assertEquals(
    options.challenge,
    '44GT44KT44Gr44Gh44Gv',
  );
});

Deno.test('should use custom supported algorithm IDs as-is when provided', async () => {
  const options = await generateRegistrationOptions({
    rpID: 'not.real',
    rpName: 'SimpleWebAuthn',
    userID: '1234',
    userName: 'usernameHere',
    supportedAlgorithmIDs: [-7, -8, -65535],
  });

  assertEquals(
    options.pubKeyCredParams,
    [
      { alg: -7, type: 'public-key' },
      { alg: -8, type: 'public-key' },
      { alg: -65535, type: 'public-key' },
    ],
  );
});

Deno.test('should require resident key if residentKey option is absent but requireResidentKey is set to true', async () => {
  const options = await generateRegistrationOptions({
    rpID: 'not.real',
    rpName: 'SimpleWebAuthn',
    userID: '1234',
    userName: 'usernameHere',
    authenticatorSelection: {
      requireResidentKey: true,
    },
  });

  assertEquals(options.authenticatorSelection?.requireResidentKey, true);
  assertEquals(options.authenticatorSelection?.residentKey, 'required');
});

Deno.test('should discourage resident key if residentKey option is absent but requireResidentKey is set to false', async () => {
  const options = await generateRegistrationOptions({
    rpID: 'not.real',
    rpName: 'SimpleWebAuthn',
    userID: '1234',
    userName: 'usernameHere',
    authenticatorSelection: {
      requireResidentKey: false,
    },
  });

  assertEquals(options.authenticatorSelection?.requireResidentKey, false);
  assertEquals(options.authenticatorSelection?.residentKey, undefined);
});

Deno.test('should prefer resident key if both residentKey and requireResidentKey options are absent', async () => {
  const options = await generateRegistrationOptions({
    rpID: 'not.real',
    rpName: 'SimpleWebAuthn',
    userID: '1234',
    userName: 'usernameHere',
  });

  assertEquals(options.authenticatorSelection?.requireResidentKey, false);
  assertEquals(options.authenticatorSelection?.residentKey, 'preferred');
});

Deno.test('should set requireResidentKey to true if residentKey if set to required', async () => {
  const options = await generateRegistrationOptions({
    rpID: 'not.real',
    rpName: 'SimpleWebAuthn',
    userID: '1234',
    userName: 'usernameHere',
    authenticatorSelection: {
      residentKey: 'required',
    },
  });

  assertEquals(options.authenticatorSelection?.requireResidentKey, true);
  assertEquals(options.authenticatorSelection?.residentKey, 'required');
});

Deno.test('should set requireResidentKey to false if residentKey if set to preferred', async () => {
  const options = await generateRegistrationOptions({
    rpID: 'not.real',
    rpName: 'SimpleWebAuthn',
    userID: '1234',
    userName: 'usernameHere',
    authenticatorSelection: {
      residentKey: 'preferred',
    },
  });

  assertEquals(options.authenticatorSelection?.requireResidentKey, false);
  assertEquals(options.authenticatorSelection?.residentKey, 'preferred');
});

Deno.test('should set requireResidentKey to false if residentKey if set to discouraged', async () => {
  const options = await generateRegistrationOptions({
    rpID: 'not.real',
    rpName: 'SimpleWebAuthn',
    userID: '1234',
    userName: 'usernameHere',
    authenticatorSelection: {
      residentKey: 'discouraged',
    },
  });

  assertEquals(options.authenticatorSelection?.requireResidentKey, false);
  assertEquals(options.authenticatorSelection?.residentKey, 'discouraged');
});

Deno.test('should prefer Ed25519 in pubKeyCredParams', async () => {
  const options = await generateRegistrationOptions({
    rpName: 'SimpleWebAuthn',
    rpID: 'not.real',
    challenge: 'totallyrandomvalue',
    userID: '1234',
    userName: 'usernameHere',
  });

  assertEquals(options.pubKeyCredParams[0].alg, -8);
});
