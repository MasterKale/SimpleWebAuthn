import { assert, assertEquals, assertExists } from 'https://deno.land/std@0.198.0/assert/mod.ts';

import { isoBase64URL } from '../helpers/iso/index.ts';

import { generateAuthenticationOptions } from './generateAuthenticationOptions.ts';

const challengeString = 'dG90YWxseXJhbmRvbXZhbHVl';
const challengeBuffer = isoBase64URL.toBuffer(challengeString);

Deno.test('should generate credential request options suitable for sending via JSON', async () => {
  const options = await generateAuthenticationOptions({
    allowCredentials: [
      {
        id: '1234',
        transports: ['usb', 'nfc'],
      },
      {
        id: '5678',
        transports: ['internal'],
      },
    ],
    timeout: 1,
    challenge: challengeBuffer,
  });

  assertEquals(options, {
    // base64url-encoded
    challenge: challengeString,
    allowCredentials: [
      {
        id: '1234',
        type: 'public-key',
        transports: ['usb', 'nfc'],
      },
      {
        id: '5678',
        type: 'public-key',
        transports: ['internal'],
      },
    ],
    timeout: 1,
    userVerification: 'preferred',
    extensions: undefined,
    rpId: undefined,
  });
});

Deno.test('defaults to 60 seconds if no timeout is specified', async () => {
  const options = await generateAuthenticationOptions({
    challenge: challengeBuffer,
    allowCredentials: [
      { id: '1234' },
      { id: '5678' },
    ],
  });

  assertEquals(options.timeout, 60000);
});

Deno.test('should set userVerification to "preferred" if not specified', async () => {
  const options = await generateAuthenticationOptions({
    challenge: challengeBuffer,
    allowCredentials: [
      { id: '1234' },
      { id: '5678' },
    ],
  });

  assertEquals(options.userVerification, 'preferred');
});

Deno.test('should not set allowCredentials if not specified', async () => {
  const options = await generateAuthenticationOptions({ rpID: 'test' });

  assertEquals(options.allowCredentials, undefined);
});

Deno.test('should generate without params', async () => {
  const options = await generateAuthenticationOptions();
  const { challenge, ...otherFields } = options;
  assertEquals(otherFields, {
    allowCredentials: undefined,
    extensions: undefined,
    rpId: undefined,
    timeout: 60000,
    userVerification: 'preferred',
  });
  assertEquals(typeof challenge, 'string');
});

Deno.test('should set userVerification if specified', async () => {
  const options = await generateAuthenticationOptions({
    challenge: challengeBuffer,
    allowCredentials: [
      { id: '1234' },
      { id: '5678' },
    ],
    userVerification: 'required',
  });

  assertEquals(options.userVerification, 'required');
});

Deno.test('should set extensions if specified', async () => {
  const options = await generateAuthenticationOptions({
    challenge: challengeBuffer,
    allowCredentials: [
      { id: '1234' },
      { id: '5678' },
    ],
    extensions: { appid: 'simplewebauthn' },
  });

  assertEquals(options.extensions, { appid: 'simplewebauthn' });
});

Deno.test('should generate a challenge if one is not provided', async () => {
  // @ts-ignore 2345
  const options = await generateAuthenticationOptions({
    allowCredentials: [
      { id: '1234' },
      { id: '5678' },
    ],
  });

  // Assert basic properties of the challenge
  assert(options.challenge.length >= 16);
  assert(isoBase64URL.isBase64URL(options.challenge));
});

Deno.test('should treat string challenges as UTF-8 strings', async () => {
  const options = await generateAuthenticationOptions({
    challenge: 'こんにちは',
  });

  assertEquals(
    options.challenge,
    '44GT44KT44Gr44Gh44Gv',
  );
});

Deno.test('should set rpId if specified', async () => {
  const rpID = 'simplewebauthn.dev';

  const opts = await generateAuthenticationOptions({
    allowCredentials: [],
    rpID,
  });

  assertExists(opts.rpId);
  assertEquals(opts.rpId, rpID);
});
