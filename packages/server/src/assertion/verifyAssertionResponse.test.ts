import verifyAssertionResponse from './verifyAssertionResponse';

import * as decodeClientDataJSON from '../helpers/decodeClientDataJSON';
import * as parseAuthenticatorData from '../helpers/parseAuthenticatorData';

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
  const verification = verifyAssertionResponse(
    assertionResponse,
    'https://dev.dontneeda.pw',
    authenticator,
  );

  expect(verification.verified).toEqual(true);
});

test('should throw when response origin is not expected value', () => {
  expect(() => {
    verifyAssertionResponse(
      assertionResponse,
      'https://different.address',
      authenticator,
    );
  }).toThrow();
});

test('should throw when assertion type is not webauthn.create', () => {
  // @ts-ignore 2345
  mockDecodeClientData.mockReturnValue({
    origin: assertionOrigin,
    type: 'webauthn.badtype',
  });

  expect(() => {
    verifyAssertionResponse(
      assertionResponse,
      assertionOrigin,
      authenticator,
    );
  }).toThrow();
});

test('should throw error if user was not present', () => {
  mockParseAuthData.mockReturnValue({
    flags: 0,
  });

  expect(() => {
    verifyAssertionResponse(
      assertionResponse,
      assertionOrigin,
      authenticator,
    );
  }).toThrow();
});

test('should throw error if previous counter value is not less than in response', () => {
  // This'll match the `counter` value in `assertionResponse`, simulating a potential replay attack
  const badCounter = 135;
  const badDevice = {
    ...authenticator,
    counter: badCounter,
  };

  expect(() => {
    verifyAssertionResponse(
      assertionResponse,
      assertionOrigin,
      badDevice,
    );
  }).toThrow();
});

/**
 * parsed authData: {
 *   rpIdHash: <Buffer>,
 *   flagsBuf: <Buffer>,
 *   flags: 1,
 *   counter: 135,
 *   counterBuf: <Buffer>
 * }
 */
const assertionResponse = {
  base64AuthenticatorData: 'PdxHEOnAiLIp26idVjIguzn3Ipr_RlsKZWsa-5qK-KABAAAAhw',
  base64ClientDataJSON: 'eyJjaGFsbGVuZ2UiOiJXRzVRU21RM1oyOTROR2gyTVROUk56WnViVmhMTlZZMWMwOHRP' +
    'V3BLVG5JIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoi' +
    'aHR0cHM6Ly9kZXYuZG9udG5lZWRhLnB3IiwidHlwZSI6IndlYmF1dGhuLmdldCJ9',
  base64Signature: 'MEQCIHZYFY3LsKzI0T9XRwEACl7YsYZysZ2HUw3q9f7tlq3wAiBNbyBbQMNM56P6Z00tBEZ6v' +
    'II4f9Al-p4pZw7OBpSaog',
};
const assertionOrigin = 'https://dev.dontneeda.pw';

const authenticator = {
  base64PublicKey: 'BBMQEnZRfg4ASys9kfGUj99Xlsa028wqYJZw8xuGahPQJWN3K9D9DajLxzKlY7uf_ulA5D6gh' +
    'UJ9hrouDX84S_I',
  base64CredentialID: 'wJZRtQbYjKlpiRnzet7yyVizdsj_oUhi11kFbKyO0hc5gIg-4xeaTC9YC9y9sfow6gO3jE' +
    'MoONBKNX4SmSclmQ',
  counter: 134,
};
