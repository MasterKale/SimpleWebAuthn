import { verify } from 'jsonwebtoken';
import JWTChallengeAdapter, { SignChallengePayload } from './JWTChallengeAdapter';
import {
  getAssertionOptions,
  assertionChallenge,
  assertionOrigin,
  assertionRPID,
} from '../assertion/testHelper';
import {
  attestationChallenge,
  attestationOrigin,
  attestationRPID,
  getAttestationOptions,
} from '../attestation/testHelper';
const strongSecret = '17hMcXI0AvkM7f4OWxBPwRE30D6HnoFBHAJT8Wt6AnbOh0Y9X2sXERpXaavEVEDH';

const goodBaseOptions = { secret: strongSecret, origin: 'test.test', rpID: 'test' };

test('should throw on weak secret', () => {
  try {
  } catch (e) {
    expect(e.message).toContain(
      'jwt secret seems too weak please use a secret with more than 64 chars',
    );
  }
  const adapter = new JWTChallengeAdapter(goodBaseOptions);
  expect(adapter.secret).toEqual(strongSecret);
});

test('should handle JWT expiration', () => {
  expect(new JWTChallengeAdapter(goodBaseOptions).jwtExpiration).toEqual('2m');
  expect(
    new JWTChallengeAdapter({ ...goodBaseOptions, jwtExpiration: '6m' }).jwtExpiration,
  ).toEqual('6m');
});

test('should assert', () => {
  const adapter = new JWTChallengeAdapter(goodBaseOptions);

  const response = adapter.assert({
    challenge: 'totallyrandomvalue',
    allowCredentials: [],
    rpId: 'test',
    adapters: {},
  });

  expect(response.adapters?.[adapter.key]).toBeDefined();

  const { challenge, origin, rpID } = verify(
    response.adapters?.[adapter.key],
    adapter.secret,
  ) as SignChallengePayload;

  expect(challenge).toEqual('totallyrandomvalue');
  expect(origin).toEqual('test.test');
  expect(rpID).toEqual('test');
});

test('should verify assert', () => {
  const adapter = new JWTChallengeAdapter({
    ...goodBaseOptions,
    origin: assertionOrigin,
    rpID: assertionRPID,
  });
  const opts1 = getAssertionOptions();
  // @ts-ignore
  opts1.credential.adapters = undefined;

  try {
    adapter.verifyAssert(opts1);
  } catch (e) {
    expect(e.message).toContain(`Missing ${adapter.key} key into adapters`);
  }

  const assertResponse = adapter.assert({
    challenge: assertionChallenge,
    allowCredentials: [],
    rpId: assertionRPID,
    adapters: {},
  });

  const opts2 = getAssertionOptions();
  opts2.credential.adapters = assertResponse.adapters as any;

  const response = adapter.verifyAssert(opts2);
  expect(response.expectedChallenge).toEqual(assertionChallenge);
  expect(response.expectedOrigin).toEqual(assertionOrigin);
  expect(response.expectedRPID).toEqual(assertionRPID);
});

test('should attest', () => {
  const adapter = new JWTChallengeAdapter(goodBaseOptions);

  const response = adapter.attest({
    // Challenge, base64url-encoded
    challenge: 'dG90YWxseXJhbmRvbXZhbHVl',
    rp: {
      name: 'test',
      id: 'test',
    },
    user: {
      id: 'test',
      name: 'tstd',
      displayName: 'test',
    },
    pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
    timeout: 60000,
    attestation: 'indirect',
    excludeCredentials: [],
    authenticatorSelection: {
      requireResidentKey: false,
      userVerification: 'preferred',
    },
  });

  expect(response.adapters?.[adapter.key]).toBeDefined();

  const { challenge, origin, rpID } = verify(
    response.adapters?.[adapter.key],
    adapter.secret,
  ) as SignChallengePayload;

  expect(challenge).toEqual('dG90YWxseXJhbmRvbXZhbHVl');
  expect(origin).toEqual('test.test');
  expect(rpID).toEqual('test');
});

test('should verify attest', () => {
  const adapter = new JWTChallengeAdapter({
    ...goodBaseOptions,
    origin: attestationOrigin,
    rpID: attestationRPID,
  });
  const opts1 = getAttestationOptions();
  // @ts-ignore
  opts1.credential.adapters = undefined;

  try {
    adapter.verifyAttest(opts1);
  } catch (e) {
    expect(e.message).toContain(`Missing ${adapter.key} key into adapters`);
  }

  const attestResponse = adapter.attest({
    // Challenge, base64url-encoded
    challenge: attestationChallenge,
    rp: {
      name: 'test',
      id: attestationRPID,
    },
    user: {
      id: 'test',
      name: 'test',
      displayName: 'test',
    },
    pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
    timeout: 60000,
    attestation: 'indirect',
    excludeCredentials: [],
    authenticatorSelection: {
      requireResidentKey: false,
      userVerification: 'preferred',
    },
  });

  const opts2 = getAttestationOptions();
  opts2.credential.adapters = attestResponse.adapters as any;

  const response = adapter.verifyAttest(opts2);
  expect(response.expectedChallenge).toEqual(attestationChallenge);
  expect(response.expectedOrigin).toEqual(attestationOrigin);
  expect(response.expectedRPID).toEqual(attestationRPID);
});
