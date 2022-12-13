jest.mock('../helpers/generateChallenge');

import { isoBase64URL } from '../helpers/iso';

import { generateAuthenticationOptions } from './generateAuthenticationOptions';

const challengeString = 'dG90YWxseXJhbmRvbXZhbHVl';
const challengeBuffer = isoBase64URL.toBuffer(challengeString);

test('should generate credential request options suitable for sending via JSON', () => {
  const options = generateAuthenticationOptions({
    allowCredentials: [
      {
        id: Buffer.from('1234', 'ascii'),
        type: 'public-key',
        transports: ['usb', 'nfc'],
      },
      {
        id: Buffer.from('5678', 'ascii'),
        type: 'public-key',
        transports: ['internal'],
      },
    ],
    timeout: 1,
    challenge: challengeBuffer,
  });

  expect(options).toEqual({
    // base64url-encoded
    challenge: challengeString,
    allowCredentials: [
      {
        id: 'MTIzNA',
        type: 'public-key',
        transports: ['usb', 'nfc'],
      },
      {
        id: 'NTY3OA',
        type: 'public-key',
        transports: ['internal'],
      },
    ],
    timeout: 1,
    userVerification: 'preferred',
  });
});

test('defaults to 60 seconds if no timeout is specified', () => {
  const options = generateAuthenticationOptions({
    challenge: challengeBuffer,
    allowCredentials: [
      { id: Buffer.from('1234', 'ascii'), type: 'public-key' },
      { id: Buffer.from('5678', 'ascii'), type: 'public-key' },
    ],
  });

  expect(options.timeout).toEqual(60000);
});

test('should set userVerification to "preferred" if not specified', () => {
  const options = generateAuthenticationOptions({
    challenge: challengeBuffer,
    allowCredentials: [
      { id: Buffer.from('1234', 'ascii'), type: 'public-key' },
      { id: Buffer.from('5678', 'ascii'), type: 'public-key' },
    ],
  });

  expect(options.userVerification).toEqual('preferred');
});

test('should not set allowCredentials if not specified', () => {
  const options = generateAuthenticationOptions({ rpID: 'test' });

  expect(options.allowCredentials).toEqual(undefined);
});

test('should generate without params', () => {
  const options = generateAuthenticationOptions();
  const { challenge, ...otherFields } = options;
  expect(otherFields).toEqual({
    allowCredentials: undefined,
    extensions: undefined,
    rpId: undefined,
    timeout: 60000,
    userVerification: 'preferred',
  });
  expect(typeof challenge).toEqual('string');
});

test('should set userVerification if specified', () => {
  const options = generateAuthenticationOptions({
    challenge: challengeBuffer,
    allowCredentials: [
      { id: Buffer.from('1234', 'ascii'), type: 'public-key' },
      { id: Buffer.from('5678', 'ascii'), type: 'public-key' },
    ],
    userVerification: 'required',
  });

  expect(options.userVerification).toEqual('required');
});

test('should set extensions if specified', () => {
  const options = generateAuthenticationOptions({
    challenge: challengeBuffer,
    allowCredentials: [
      { id: Buffer.from('1234', 'ascii'), type: 'public-key' },
      { id: Buffer.from('5678', 'ascii'), type: 'public-key' },
    ],
    extensions: { appid: 'simplewebauthn' },
  });

  expect(options.extensions).toEqual({
    appid: 'simplewebauthn',
  });
});

test('should generate a challenge if one is not provided', () => {
  const opts = {
    allowCredentials: [
      { id: Buffer.from('1234', 'ascii'), type: 'public-key' },
      { id: Buffer.from('5678', 'ascii'), type: 'public-key' },
    ],
  };

  // @ts-ignore 2345
  const options = generateAuthenticationOptions(opts);

  // base64url-encoded 16-byte buffer from mocked `generateChallenge()`
  expect(options.challenge).toEqual('AQIDBAUGBwgJCgsMDQ4PEA');
});

test('should set rpId if specified', () => {
  const rpID = 'simplewebauthn.dev';

  const opts = generateAuthenticationOptions({
    allowCredentials: [],
    rpID,
  });

  expect(opts.rpId).toBeDefined();
  expect(opts.rpId).toEqual(rpID);
});
