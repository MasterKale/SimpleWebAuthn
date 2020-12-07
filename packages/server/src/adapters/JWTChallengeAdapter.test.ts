import { verify } from 'jsonwebtoken';
import JWTChallengeAdapter, { SignChallengePayload } from './JWTChallengeAdapter';
import {
  getAssertionOptions,
  assertionChallenge,
  assertionOrigin,
  assertionRPID,
} from '../assertion/testHelper';
const strongSecret = '17hMcXI0AvkM7f4OWxBPwRE30D6HnoFBHAJT8Wt6AnbOh0Y9X2sXERpXaavEVEDH';

const goodBaseOptions = { secret: strongSecret, origin: 'test.test' };

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
  expect(new JWTChallengeAdapter(goodBaseOptions).jwtExpiration).toEqual('5m');
  expect(
    new JWTChallengeAdapter({ ...goodBaseOptions, jwtExpiration: '6m' }).jwtExpiration,
  ).toEqual('6m');
});

test('should assert', () => {
  const adapter = new JWTChallengeAdapter(goodBaseOptions);

  try {
    adapter.assert({
      challenge: 'totallyrandomvalue',
      allowCredentials: [],
      adapters: {},
    });
  } catch (e) {
    expect(e.message).toContain('You need to at least provide rpID on adapter');
  }

  const response = adapter.assert({
    challenge: 'totallyrandomvalue',
    allowCredentials: [],
    rpId: 'test.test',
    adapters: {},
  });

  expect(response.adapters[adapter.key]).toBeDefined();

  const { challenge, origin, rpID } = verify(
    response.adapters[adapter.key],
    adapter.secret,
  ) as SignChallengePayload;

  expect(challenge).toEqual('totallyrandomvalue');
  expect(origin).toEqual('test');
  expect(rpID).toEqual('test.test');
});

test('should verify assert', () => {
  const adapter = new JWTChallengeAdapter({ ...goodBaseOptions, origin: assertionOrigin });
  const opts1 = getAssertionOptions();
  delete opts1.credential.adapters;
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
  opts2.credential.adapters = assertResponse.adapters;

  const response = adapter.verifyAssert(opts2);
  expect(response.expectedChallenge).toEqual(assertionChallenge);
  expect(response.expectedOrigin).toEqual(assertionOrigin);
  expect(response.expectedRPID).toEqual(assertionRPID);
});
