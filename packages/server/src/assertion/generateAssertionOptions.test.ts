jest.mock('../helpers/generateChallenge');

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
    challenge: 'totallyrandomvalue',
    allowCredentials: [
      { id: Buffer.from('1234', 'ascii').toString('base64'), type: 'public-key' },
      { id: Buffer.from('5678', 'ascii').toString('base64'), type: 'public-key' },
    ],
  };
  delete opts.challenge;

  // @ts-ignore 2345
  const options = generateAssertionOptions(opts);

  // base64url-encoded 16-byte buffer from mocked `generateChallenge()`
  expect(options.challenge).toEqual('AQIDBAUGBwgJCgsMDQ4PEA');
});
