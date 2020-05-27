import generateAssertionOptions from './generateAssertionOptions';

test('should generate credential request options suitable for sending via JSON', () => {
  const challenge = 'totallyrandomvalue';

  const options = generateAssertionOptions({
    ...goodOpts1,
    timeout: 1,
    challenge,
  });

  expect(options).toEqual({
    challenge,
    allowCredentials: [
      {
        id: 'MTIzNA==',
        type: 'public-key',
        transports: ['usb', 'ble', 'nfc', 'internal'],
      },
      {
        id: 'NTY3OA==',
        type: 'public-key',
        transports: ['usb', 'ble', 'nfc', 'internal'],
      },
    ],
    timeout: 1,
  });
});

test('defaults to 60 seconds if no timeout is specified', () => {
  const options = generateAssertionOptions(goodOpts1);

  expect(options.timeout).toEqual(60000);
});

test('should not set userVerification if not specified', () => {
  const options = generateAssertionOptions({
    ...goodOpts1,
  });

  expect(options.userVerification).toEqual(undefined);
});

test('should set userVerification if specified', () => {
  const options = generateAssertionOptions({
    ...goodOpts1,
    userVerification: 'required',
  });

  expect(options.userVerification).toEqual('required');
});

const goodOpts1 = {
  challenge: 'totallyrandomvalue',
  allowedBase64CredentialIDs: [
    Buffer.from('1234', 'ascii').toString('base64'),
    Buffer.from('5678', 'ascii').toString('base64'),
  ],
};
