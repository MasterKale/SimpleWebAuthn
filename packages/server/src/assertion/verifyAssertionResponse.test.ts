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
    assertionOrigin,
    authenticator,
  );

  expect(verification.verified).toEqual(true);
});

test('should return authenticator info after verification', () => {
  const verification = verifyAssertionResponse(
    assertionResponse,
    assertionOrigin,
    authenticator,
  );

  expect(verification.authenticatorInfo.counter).toEqual(144);
  expect(verification.authenticatorInfo.base64CredentialID).toEqual(authenticator.base64CredentialID);
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
  const badCounter = 144;
  const badDevice = {
    ...authenticator,
    counter: badCounter,
  };

  expect(() => {
    console.log(verifyAssertionResponse(
      assertionResponse,
      assertionOrigin,
      badDevice,
    ));
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
  base64CredentialID: 'KEbWNCc7NgaYnUyrNeFGX9_3Y-8oJ3KwzjnaiD1d1LVTxR7v3CaKfCz2Vy_g_MHSh7yJ8yL0Px' +
    'g6jo_o0hYiew',
  base64AuthenticatorData: 'PdxHEOnAiLIp26idVjIguzn3Ipr_RlsKZWsa-5qK-KABAAAAkA==',
  base64ClientDataJSON: 'eyJjaGFsbGVuZ2UiOiJkRzkwWVd4c2VWVnVhWEYxWlZaaGJIVmxSWFpsY25sVWFXMWwiLCJj' +
    'bGllbnRFeHRlbnNpb25zIjp7fSwiaGFzaEFsZ29yaXRobSI6IlNIQS0yNTYiLCJvcmlnaW4iOiJodHRwczovL2Rldi5k' +
    'b250bmVlZGEucHciLCJ0eXBlIjoid2ViYXV0aG4uZ2V0In0=',
  base64Signature: 'MEUCIQDYXBOpCWSWq2Ll4558GJKD2RoWg958lvJSB_GdeokxogIgWuEVQ7ee6AswQY0OsuQ6y8Ks6' +
    'jhd45bDx92wjXKs900='
};
const assertionOrigin = 'https://dev.dontneeda.pw';

const authenticator = {
  base64PublicKey: 'BIheFp-u6GvFT2LNGovf3ZrT0iFVBsA_76rRysxRG9A18WGeA6hPmnab0HAViUYVRkwTNcN77QBf_' +
    'RR0dv3lIvQ',
  base64CredentialID: 'KEbWNCc7NgaYnUyrNeFGX9_3Y-8oJ3KwzjnaiD1d1LVTxR7v3CaKfCz2Vy_g_MHSh7yJ8yL0Px' +
    'g6jo_o0hYiew',
  counter: 0,
};
