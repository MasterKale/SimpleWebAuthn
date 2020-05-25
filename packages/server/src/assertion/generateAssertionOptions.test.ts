import generateAssertionOptions from './generateAssertionOptions';

test('should generate credential request options suitable for sending via JSON', () => {
  const challenge = 'totallyrandomvalue';

  const options = generateAssertionOptions(
    challenge,
    [
      Buffer.from('1234', 'ascii').toString('base64'),
      Buffer.from('5678', 'ascii').toString('base64'),
    ],
    1,
  );

  expect(options).toEqual({
    publicKey: {
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
    },
  });
});

test('defaults to 60 seconds if no timeout is specified', () => {
  const options = generateAssertionOptions(
    'totallyrandomvalue',
    [
      Buffer.from('1234', 'ascii').toString('base64'),
      Buffer.from('5678', 'ascii').toString('base64'),
    ],
  );

  expect(options.publicKey.timeout).toEqual(60000);
});
