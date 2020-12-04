jest.mock('../helpers/generateChallenge');
import { verify } from 'jsonwebtoken';
import verifyChallenge from '../helpers/verifyChallenge';

import generateAssertionOptions from './generateAssertionOptions';

test('should generate credential request options suitable for sending via JSON', () => {
  const challenge = 'totallyrandomvalue';

  const options = generateAssertionOptions({
    allowCredentials: [
      {
        id: Buffer.from('1234', 'ascii').toString('base64'),
        type: 'public-key',
        transports: ['usb', 'nfc'],
      },
      {
        id: Buffer.from('5678', 'ascii').toString('base64'),
        type: 'public-key',
        transports: ['internal'],
      },
    ],
    timeout: 1,
    challenge,
  });

  expect(options).toEqual({
    // base64url-encoded
    challenge: 'dG90YWxseXJhbmRvbXZhbHVl',
    allowCredentials: [
      {
        id: 'MTIzNA==',
        type: 'public-key',
        transports: ['usb', 'nfc'],
      },
      {
        id: 'NTY3OA==',
        type: 'public-key',
        transports: ['internal'],
      },
    ],
    timeout: 1,
  });
});

test('defaults to 60 seconds if no timeout is specified', () => {
  const options = generateAssertionOptions({
    challenge: 'totallyrandomvalue',
    allowCredentials: [
      { id: Buffer.from('1234', 'ascii').toString('base64'), type: 'public-key' },
      { id: Buffer.from('5678', 'ascii').toString('base64'), type: 'public-key' },
    ],
  });

  expect(options.timeout).toEqual(60000);
});

test('should not set userVerification if not specified', () => {
  const options = generateAssertionOptions({
    challenge: 'totallyrandomvalue',
    allowCredentials: [
      { id: Buffer.from('1234', 'ascii').toString('base64'), type: 'public-key' },
      { id: Buffer.from('5678', 'ascii').toString('base64'), type: 'public-key' },
    ],
  });

  expect(options.userVerification).toEqual(undefined);
});

test('should set userVerification if specified', () => {
  const options = generateAssertionOptions({
    challenge: 'totallyrandomvalue',
    allowCredentials: [
      { id: Buffer.from('1234', 'ascii').toString('base64'), type: 'public-key' },
      { id: Buffer.from('5678', 'ascii').toString('base64'), type: 'public-key' },
    ],
    userVerification: 'required',
  });

  expect(options.userVerification).toEqual('required');
});

test('should set extensions if specified', () => {
  const options = generateAssertionOptions({
    challenge: 'totallyrandomvalue',
    allowCredentials: [
      { id: Buffer.from('1234', 'ascii').toString('base64'), type: 'public-key' },
      { id: Buffer.from('5678', 'ascii').toString('base64'), type: 'public-key' },
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
      { id: Buffer.from('1234', 'ascii').toString('base64'), type: 'public-key' },
      { id: Buffer.from('5678', 'ascii').toString('base64'), type: 'public-key' },
    ],
  };

  // @ts-ignore 2345
  const options = generateAssertionOptions(opts);

  // base64url-encoded 16-byte buffer from mocked `generateChallenge()`
  expect(options.challenge).toEqual('AQIDBAUGBwgJCgsMDQ4PEA');
});

test('should set rpId if specified', () => {
  const rpID = 'simplewebauthn.dev';

  const opts = generateAssertionOptions({
    allowCredentials: [],
    rpID,
  });

  expect(opts.rpId).toBeDefined();
  expect(opts.rpId).toEqual(rpID);
});

test('should set signedChallenge if serverSecret specified', () => {
  const serverSecret = '17hMcXI0AvkM7f4OWxBPwRE30D6HnoFBHAJT8Wt6AnbOh0Y9X2sXERpXaavEVEDH';

  const opts = generateAssertionOptions({
    allowCredentials: [],
    serverSecret,
    rpID: 'test',
    origin: 'test',
  });

  expect(opts.signedChallenge).toBeDefined();
  const verifiedChallenge = verifyChallenge(opts.signedChallenge, serverSecret);
  expect(verifiedChallenge.challenge).toEqual(opts.challenge);
  expect(verifiedChallenge.rpID).toEqual(opts.rpId);
  expect(verifiedChallenge.origin).toEqual('test');
});
