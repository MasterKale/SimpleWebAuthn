import { verify } from 'jsonwebtoken';
import JWTChallengeAdapter, { SignChallengePayload } from './JWTChallengeAdapter';
import {
  getVerifyAssertOptions,
  getAssertResponse,
  assertionChallenge,
  assertionOrigin,
  assertionRPID,
} from '../assertion/testHelper';
import {
  attestationChallenge,
  attestationOrigin,
  attestationRPID,
  getAttestResponse,
  getVerifyAttestOptions,
} from '../attestation/testHelper';
const strongSecret = '17hMcXI0AvkM7f4OWxBPwRE30D6HnoFBHAJT8Wt6AnbOh0Y9X2sXERpXaavEVEDH';

const goodBaseOptions = { secretOrPrivateKey: strongSecret, origin: 'test.test', rpID: 'test' };

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

test('should have default jwt options', () => {
  expect(new JWTChallengeAdapter(goodBaseOptions).jwtOptions).toEqual({
    verify: { algorithms: ['HS256'] },
    sign: { algorithm: 'HS256', expiresIn: '2m' },
  });
});

test('should handle JWT options', () => {
  expect(
    new JWTChallengeAdapter({
      ...goodBaseOptions,
      jwtOptions: {
        verify: { algorithms: ['RS512'] },
        sign: { algorithm: 'RS512', expiresIn: '10m' },
      },
    }).jwtOptions,
  ).toEqual({
    verify: { algorithms: ['RS512'] },
    sign: { algorithm: 'RS512', expiresIn: '10m' },
  });
});

test('should assert', () => {
  const adapter = new JWTChallengeAdapter(goodBaseOptions);

  const response = adapter.assert(getAssertResponse());

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
  const opts1 = getVerifyAssertOptions();
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

  const opts2 = getVerifyAssertOptions();
  opts2.credential.adapters = assertResponse.adapters as any;

  const response = adapter.verifyAssert(opts2);
  expect(response.expectedChallenge).toEqual(assertionChallenge);
  expect(response.expectedOrigin).toEqual(assertionOrigin);
  expect(response.expectedRPID).toEqual(assertionRPID);
});

test('should attest', () => {
  const adapter = new JWTChallengeAdapter(goodBaseOptions);

  const response = adapter.attest(getAttestResponse());

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
  const opts1 = getVerifyAttestOptions();
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

  const opts2 = getVerifyAttestOptions();
  opts2.credential.adapters = attestResponse.adapters as any;

  const response = adapter.verifyAttest(opts2);
  expect(response.expectedChallenge).toEqual(attestationChallenge);
  expect(response.expectedOrigin).toEqual(attestationOrigin);
  expect(response.expectedRPID).toEqual(attestationRPID);
});
