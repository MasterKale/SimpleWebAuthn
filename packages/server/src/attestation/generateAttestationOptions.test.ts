import generateAttestationOptions from './generateAttestationOptions';

test('should generate credential request options suitable for sending via JSON', () => {
  const serviceName = 'WebAuthntine';
  const rpID = 'not.real';
  const challenge = 'totallyrandomvalue';
  const userID = '1234';
  const username = 'usernameHere';
  const timeout = 1;
  const attestationType = 'indirect';
  const excludeCredentials = ['123abc'];

  const options = generateAttestationOptions(
    serviceName,
    rpID,
    challenge,
    userID,
    username,
    timeout,
    attestationType,
    excludeCredentials,
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
      pubKeyCredParams: [{
        alg: -7,
        type: 'public-key',
      }],
      timeout,
      attestation: attestationType,
      excludeCredentials: [{
        type: 'public-key',
        id: '123abc'
      }],
    },
  });
});

test('defaults to 60 seconds if no timeout is specified', () => {
  const options = generateAttestationOptions(
    'WebAuthntine',
    'not.real',
    'totallyrandomvalue',
    '1234',
    'usernameHere',
  );

  expect(options.publicKey.timeout).toEqual(60000);
});

test('defaults to direct attestation if no attestation type is specified', () => {
  const options = generateAttestationOptions(
    'WebAuthntine',
    'not.real',
    'totallyrandomvalue',
    '1234',
    'usernameHere',
  );

  expect(options.publicKey.attestation).toEqual('direct');
});