import verifyAssertionResponse from './verifyAssertionResponse';

import * as decodeClientDataJSON from '../helpers/decodeClientDataJSON';
import * as parseAuthenticatorData from '../helpers/parseAuthenticatorData';
import toHash from '../helpers/toHash';

let mockDecodeClientData: jest.SpyInstance;
let mockParseAuthData: jest.SpyInstance;

beforeEach(() => {
  mockDecodeClientData = jest.spyOn(decodeClientDataJSON, 'default');
  mockParseAuthData = jest.spyOn(parseAuthenticatorData, 'default');
});

afterEach(() => {
  mockDecodeClientData.mockRestore();
  mockParseAuthData.mockRestore();
});

test('should verify an assertion response', () => {
  const verification = verifyAssertionResponse({
    credential: assertionResponse,
    expectedChallenge: assertionChallenge,
    expectedOrigin: assertionOrigin,
    expectedRPID: 'dev.dontneeda.pw',
    authenticator: authenticator,
  });

  expect(verification.verified).toEqual(true);
});

test('should return authenticator info after verification', () => {
  const verification = verifyAssertionResponse({
    credential: assertionResponse,
    expectedChallenge: assertionChallenge,
    expectedOrigin: assertionOrigin,
    expectedRPID: 'dev.dontneeda.pw',
    authenticator: authenticator,
  });

  expect(verification.authenticatorInfo.counter).toEqual(144);
  expect(verification.authenticatorInfo.base64CredentialID).toEqual(authenticator.credentialID);
});

test('should throw when response challenge is not expected value', () => {
  expect(() => {
    verifyAssertionResponse({
      credential: assertionResponse,
      expectedChallenge: 'shouldhavebeenthisvalue',
      expectedOrigin: 'https://different.address',
      expectedRPID: 'dev.dontneeda.pw',
      authenticator: authenticator,
    });
  }).toThrow(/assertion challenge/i);
});

test('should throw when response origin is not expected value', () => {
  expect(() => {
    verifyAssertionResponse({
      credential: assertionResponse,
      expectedChallenge: assertionChallenge,
      expectedOrigin: 'https://different.address',
      expectedRPID: 'dev.dontneeda.pw',
      authenticator: authenticator,
    });
  }).toThrow(/assertion origin/i);
});

test('should throw when assertion type is not webauthn.create', () => {
  // @ts-ignore 2345
  mockDecodeClientData.mockReturnValue({
    origin: assertionOrigin,
    type: 'webauthn.badtype',
    challenge: assertionChallenge,
  });

  expect(() => {
    verifyAssertionResponse({
      credential: assertionResponse,
      expectedChallenge: assertionChallenge,
      expectedOrigin: assertionOrigin,
      expectedRPID: 'dev.dontneeda.pw',
      authenticator: authenticator,
    });
  }).toThrow(/assertion type/i);
});

test('should throw error if user was not present', () => {
  mockParseAuthData.mockReturnValue({
    rpIdHash: toHash(Buffer.from('dev.dontneeda.pw', 'ascii')),
    flags: 0,
  });

  expect(() => {
    verifyAssertionResponse({
      credential: assertionResponse,
      expectedChallenge: assertionChallenge,
      expectedOrigin: assertionOrigin,
      expectedRPID: 'dev.dontneeda.pw',
      authenticator: authenticator,
    });
  }).toThrow(/not present/i);
});

test('should throw error if previous counter value is not less than in response', () => {
  // This'll match the `counter` value in `assertionResponse`, simulating a potential replay attack
  const badCounter = 144;
  const badDevice = {
    ...authenticator,
    counter: badCounter,
  };

  expect(() => {
    verifyAssertionResponse({
      credential: assertionResponse,
      expectedChallenge: assertionChallenge,
      expectedOrigin: assertionOrigin,
      expectedRPID: 'dev.dontneeda.pw',
      authenticator: badDevice,
    });
  }).toThrow(/counter value/i);
});

test('should not compare counters if both are 0', () => {
  const verification = verifyAssertionResponse({
    credential: assertionFirstTimeUsedResponse,
    expectedChallenge: assertionFirstTimeUsedChallenge,
    expectedOrigin: assertionFirstTimeUsedOrigin,
    expectedRPID: 'dev.dontneeda.pw',
    authenticator: authenticatorFirstTimeUsed,
  });

  expect(verification.verified).toEqual(true);
});

const assertionResponse = {
  id: 'KEbWNCc7NgaYnUyrNeFGX9_3Y-8oJ3KwzjnaiD1d1LVTxR7v3CaKfCz2Vy_g_MHSh7yJ8yL0Pxg6jo_o0hYiew',
  rawId: '',
  response: {
    authenticatorData: 'PdxHEOnAiLIp26idVjIguzn3Ipr_RlsKZWsa-5qK-KABAAAAkA==',
    clientDataJSON:
      'eyJjaGFsbGVuZ2UiOiJkRzkwWVd4c2VWVnVhWEYxWlZaaGJIVmxSWFpsY25sVWFXMWwiLCJj' +
      'bGllbnRFeHRlbnNpb25zIjp7fSwiaGFzaEFsZ29yaXRobSI6IlNIQS0yNTYiLCJvcmlnaW4iOiJodHRwczovL2Rldi5k' +
      'b250bmVlZGEucHciLCJ0eXBlIjoid2ViYXV0aG4uZ2V0In0=',
    signature:
      'MEUCIQDYXBOpCWSWq2Ll4558GJKD2RoWg958lvJSB_GdeokxogIgWuEVQ7ee6AswQY0OsuQ6y8Ks6' +
      'jhd45bDx92wjXKs900=',
  },
  getClientExtensionResults: () => ({}),
  type: 'webauthn.get',
};
const assertionChallenge = 'totallyUniqueValueEveryTime';
const assertionOrigin = 'https://dev.dontneeda.pw';

const authenticator = {
  publicKey:
    'BIheFp-u6GvFT2LNGovf3ZrT0iFVBsA_76rRysxRG9A18WGeA6hPmnab0HAViUYVRkwTNcN77QBf_' + 'RR0dv3lIvQ',
  credentialID:
    'KEbWNCc7NgaYnUyrNeFGX9_3Y-8oJ3KwzjnaiD1d1LVTxR7v3CaKfCz2Vy_g_MHSh7yJ8yL0Px' + 'g6jo_o0hYiew',
  counter: 0,
};

/**
 * Represented a device that's being used on the website for the first time
 */
const assertionFirstTimeUsedResponse = {
  id: 'wSisR0_4hlzw3Y1tj4uNwwifIhRa-ZxWJwWbnfror0pVK9qPdBPO5pW3gasPqn6wXHb0LNhXB_IrA1nFoSQJ9A',
  rawId: 'wSisR0_4hlzw3Y1tj4uNwwifIhRa-ZxWJwWbnfror0pVK9qPdBPO5pW3gasPqn6wXHb0LNhXB_IrA1nFoSQJ9A',
  response: {
    authenticatorData: 'PdxHEOnAiLIp26idVjIguzn3Ipr_RlsKZWsa-5qK-KABAAAAAA',
    clientDataJSON:
      'eyJjaGFsbGVuZ2UiOiJkRzkwWVd4c2VWVnVhWEYxWlZaaGJIVmxSWFpsY25sQmMzTmxjblJwYjI0IiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9kZXYuZG9udG5lZWRhLnB3IiwidHlwZSI6IndlYmF1dGhuLmdldCJ9',
    signature:
      'MEQCIBu6M-DGzu1O8iocGHEj0UaAZm0HmxTeRIE6-nS3_CPjAiBDsmIzy5sacYwwzgpXqfwRt_2vl5yiQZ_OAqWJQBGVsQ',
  },
  type: 'public-key',
};
const assertionFirstTimeUsedChallenge = 'totallyUniqueValueEveryAssertion';
const assertionFirstTimeUsedOrigin = 'https://dev.dontneeda.pw';
const authenticatorFirstTimeUsed = {
  publicKey:
    'BGmaxR4mBbukc2QhtW2ldhAAd555r-ljlGQN8MbcTnPP9CyUlE-0AB2fbzZbNgBvJuRa7r6o2jPphOmtyNPR_kY',
  credentialID:
    'wSisR0_4hlzw3Y1tj4uNwwifIhRa-ZxWJwWbnfror0pVK9qPdBPO5pW3gasPqn6wXHb0LNhXB_IrA1nFoSQJ9A',
  counter: 0,
};
