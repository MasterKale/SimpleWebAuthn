import generateAttestationOptions from './generateAttestationOptions';

test('should generate credential request options suitable for sending via JSON', () => {
  const serviceName = 'SimpleWebAuthn';
  const rpID = 'not.real';
  const challenge = 'totallyrandomvalue';
  const userID = '1234';
  const userName = 'usernameHere';
  const timeout = 1;
  const attestationType = 'indirect';

  const options = generateAttestationOptions({
    serviceName,
    rpID,
    challenge,
    userID,
    userName,
    timeout,
    attestationType,
  });

  expect(options).toEqual({
    challenge,
    rp: {
      name: serviceName,
      id: rpID,
    },
    user: {
      id: userID,
      name: userName,
      displayName: userName,
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
  });
});

test('should map excluded credential IDs if specified', () => {
  const options = generateAttestationOptions({
    serviceName: 'SimpleWebAuthn',
    rpID: 'not.real',
    challenge: 'totallyrandomvalue',
    userID: '1234',
    userName: 'usernameHere',
    excludedBase64CredentialIDs: ['someIDhere'],
  });

  expect(options.excludeCredentials).toEqual([{
    id: 'someIDhere',
    type: 'public-key',
    transports: ['usb', 'ble', 'nfc', 'internal'],
  }]);
});

test('defaults to 60 seconds if no timeout is specified', () => {
  const options = generateAttestationOptions({
    serviceName: 'SimpleWebAuthn',
    rpID: 'not.real',
    challenge: 'totallyrandomvalue',
    userID: '1234',
    userName: 'usernameHere',
  });

  expect(options.timeout).toEqual(60000);
});

test('defaults to direct attestation if no attestation type is specified', () => {
  const options = generateAttestationOptions({
    serviceName: 'SimpleWebAuthn',
    rpID: 'not.real',
    challenge: 'totallyrandomvalue',
    userID: '1234',
    userName: 'usernameHere',
  });

  expect(options.attestation).toEqual('none');
});

test('should set authenticatorAttributes to authenticatorSelection if set', () => {
  const options = generateAttestationOptions({
    serviceName: 'SimpleWebAuthn',
    rpID: 'not.real',
    challenge: 'totallyrandomvalue',
    userID: '1234',
    userName: 'usernameHere',
    authenticatorAttributes: {
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
