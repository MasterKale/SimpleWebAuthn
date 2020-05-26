import generateAttestationOptions from './generateAttestationOptions';

test('should generate credential request options suitable for sending via JSON', () => {
  const serviceName = 'SimpleWebAuthn';
  const rpID = 'not.real';
  const challenge = 'totallyrandomvalue';
  const userID = '1234';
  const username = 'usernameHere';
  const timeout = 1;
  const attestationType = 'indirect';

  const options = generateAttestationOptions(
    serviceName,
    rpID,
    challenge,
    userID,
    username,
    timeout,
    attestationType,
  );

  expect(options).toEqual({
    publicKey: {
      challenge,
      rp: {
        name: serviceName,
        id: rpID,
      },
      user: {
        id: userID,
        name: username,
        displayName: username,
      },
      pubKeyCredParams: [
        {
          alg: -7,
          type: 'public-key',
        },
      ],
      timeout,
      attestation: attestationType,
      excludeCredentials: [],
    },
  });
});

test('should map excluded credential IDs if specified', () => {
  const options = generateAttestationOptions(
    'SimpleWebAuthn',
    'not.real',
    'totallyrandomvalue',
    '1234',
    'usernameHere',
    undefined,
    undefined,
    ['someIDhere'],
  );

  expect(options.publicKey.excludeCredentials).toEqual([{
    id: 'someIDhere',
    type: 'public-key',
    transports: ['usb', 'ble', 'nfc', 'internal'],
  }]);
});

test('defaults to 60 seconds if no timeout is specified', () => {
  const options = generateAttestationOptions(
    'SimpleWebAuthn',
    'not.real',
    'totallyrandomvalue',
    '1234',
    'usernameHere',
  );

  expect(options.publicKey.timeout).toEqual(60000);
});

test('defaults to direct attestation if no attestation type is specified', () => {
  const options = generateAttestationOptions(
    'SimpleWebAuthn',
    'not.real',
    'totallyrandomvalue',
    '1234',
    'usernameHere',
  );

  expect(options.publicKey.attestation).toEqual('direct');
});
