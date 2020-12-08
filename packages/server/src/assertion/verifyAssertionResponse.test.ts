import base64url from 'base64url';
import verifyAssertionResponse from './verifyAssertionResponse';

import * as decodeClientDataJSON from '../helpers/decodeClientDataJSON';
import * as parseAuthenticatorData from '../helpers/parseAuthenticatorData';
import toHash from '../helpers/toHash';
import {
  assertionResponse,
  assertionOrigin,
  assertionChallenge,
  authenticator,
  assertionRPID,
} from './testHelper';
import EmptyAdapter from '../adapters/EmptyAdapter';

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
    expectedRPID: assertionRPID,
    authenticator: authenticator,
  });

  expect(verification.verified).toEqual(true);
});

test('should return authenticator info after verification', () => {
  const verification = verifyAssertionResponse({
    credential: assertionResponse,
    expectedChallenge: assertionChallenge,
    expectedOrigin: assertionOrigin,
    expectedRPID: assertionRPID,
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
      expectedRPID: assertionRPID,
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
      expectedRPID: assertionRPID,
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
      expectedRPID: assertionRPID,
      authenticator: authenticator,
    });
  }).toThrow(/assertion type/i);
});

test('should throw error if user was not present', () => {
  mockParseAuthData.mockReturnValue({
    rpIdHash: toHash(Buffer.from(assertionRPID, 'ascii')),
    flags: 0,
  });

  expect(() => {
    verifyAssertionResponse({
      credential: assertionResponse,
      expectedChallenge: assertionChallenge,
      expectedOrigin: assertionOrigin,
      expectedRPID: assertionRPID,
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
      expectedRPID: assertionRPID,
      authenticator: badDevice,
    });
  }).toThrow(/counter value/i);
});

test('should throw error if assertion RP ID is unexpected value', () => {
  mockParseAuthData.mockReturnValue({
    rpIdHash: toHash(Buffer.from('bad.url', 'ascii')),
    flags: 0,
  });

  expect(() => {
    verifyAssertionResponse({
      credential: assertionResponse,
      expectedChallenge: assertionChallenge,
      expectedOrigin: assertionOrigin,
      expectedRPID: assertionRPID,
      authenticator: authenticator,
    });
  }).toThrow(/rp id/i);
});

test('should not compare counters if both are 0', () => {
  const verification = verifyAssertionResponse({
    credential: assertionFirstTimeUsedResponse,
    expectedChallenge: assertionFirstTimeUsedChallenge,
    expectedOrigin: assertionFirstTimeUsedOrigin,
    expectedRPID: assertionRPID,
    authenticator: authenticatorFirstTimeUsed,
  });

  expect(verification.verified).toEqual(true);
});

test('should throw an error if user verification is required but user was not verified', () => {
  const actualData = parseAuthenticatorData.default(
    base64url.toBuffer(assertionResponse.response.authenticatorData),
  );

  mockParseAuthData.mockReturnValue({
    ...actualData,
    flags: {
      up: true,
      uv: false,
    },
  });

  expect(() => {
    verifyAssertionResponse({
      credential: assertionResponse,
      expectedChallenge: assertionChallenge,
      expectedOrigin: assertionOrigin,
      expectedRPID: assertionRPID,
      authenticator: authenticator,
      fidoUserVerification: 'required',
    });
  }).toThrow(/user could not be verified/i);
});

test('should use adapters if provided', () => {
  EmptyAdapter.prototype.verifyAssert = jest.fn().mockImplementation(o => o);
  const opts = {
    credential: assertionResponse,
    expectedChallenge: assertionChallenge,
    expectedOrigin: assertionOrigin,
    expectedRPID: assertionRPID,
    authenticator: authenticator,
    adapters: [new EmptyAdapter(), new EmptyAdapter()],
  };

  verifyAssertionResponse(opts);

  expect(EmptyAdapter.prototype.verifyAssert).toHaveBeenNthCalledWith(2, opts);
});

// TODO: Get a real TPM assertion in here
test.skip('should verify TPM assertion', () => {
  const expectedChallenge = 'dG90YWxseVVuaXF1ZVZhbHVlRXZlcnlBc3NlcnRpb24';
  jest.spyOn(base64url, 'encode').mockReturnValueOnce(expectedChallenge);
  const verification = verifyAssertionResponse({
    credential: {
      id: 'YJ8FMM-AmcUt73XPX341WXWd7ypBMylGjjhu0g3VzME',
      rawId: 'YJ8FMM-AmcUt73XPX341WXWd7ypBMylGjjhu0g3VzME',
      response: {
        authenticatorData: 'PdxHEOnAiLIp26idVjIguzn3Ipr_RlsKZWsa-5qK-KAFAAAAAQ',
        clientDataJSON:
          'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiZEc5MFlXeHNlVlZ1YVhGMVpWWmhiSFZsUlhabGNubEJjM05sY25ScGIyNCIsIm9yaWdpbiI6Imh0dHBzOi8vZGV2LmRvbnRuZWVkYS5wdyIsImNyb3NzT3JpZ2luIjpmYWxzZX0',
        signature:
          'T6nS6IDnfXmt_f2BEzIvw86RrHCpmf_OQIbiY-OBgk4jyKakYF34tnpdajQnIHTCa3-56RWDa_tZGQwZopEcrWRgSONKnMEboNhsw0aTYDo2q4fICD33qVFUuBIEcWJJyv1RqfW3uvPZAq1yvif81xPWYgF796fx7fFZzbBQARbUjNPudBuwgONljRbDstRhqnrP_b7h0-_CQ8EBJIR7Bor-R5I6JYsNWeR9r0wRPkpIhNRND-y6or6Shm2NXhr-ovLtnzpdouzlrJUJWnBJquWAjtiXKZsGfsY9Srh7jduoyKyPkwItPewcdlV30uUFCtPMepaJ5lUwbBtRE0NsXg',
        userHandle: 'aW50ZXJuYWxVc2VySWQ',
      },
      type: 'public-key',
    },
    expectedChallenge,
    expectedOrigin: assertionOrigin,
    expectedRPID: assertionRPID,
    authenticator: {
      publicKey: 'BAEAAQ',
      credentialID: 'YJ8FMM-AmcUt73XPX341WXWd7ypBMylGjjhu0g3VzME',
      counter: 0,
    },
  });

  expect(verification.verified).toEqual(true);
});

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
const assertionFirstTimeUsedChallenge = base64url.encode('totallyUniqueValueEveryAssertion');
const assertionFirstTimeUsedOrigin = 'https://dev.dontneeda.pw';
const authenticatorFirstTimeUsed = {
  publicKey:
    'pQECAyYgASFYIGmaxR4mBbukc2QhtW2ldhAAd555r-ljlGQN8MbcTnPPIlgg9CyUlE-0AB2fbzZbNgBvJuRa7r6o2jPphOmtyNPR_kY',
  credentialID:
    'wSisR0_4hlzw3Y1tj4uNwwifIhRa-ZxWJwWbnfror0pVK9qPdBPO5pW3gasPqn6wXHb0LNhXB_IrA1nFoSQJ9A',
  counter: 0,
};
