import base64url from 'base64url';

import verifyAttestationResponse from './verifyAttestationResponse';

import * as decodeAttestationObject from '../helpers/decodeAttestationObject';
import * as decodeClientDataJSON from '../helpers/decodeClientDataJSON';
import * as parseAuthenticatorData from '../helpers/parseAuthenticatorData';
import * as decodeCredentialPublicKey from '../helpers/decodeCredentialPublicKey';

import * as verifyFIDOU2F from './verifications/verifyFIDOU2F';

import toHash from '../helpers/toHash';

let mockDecodeAttestation: jest.SpyInstance;
let mockDecodeClientData: jest.SpyInstance;
let mockParseAuthData: jest.SpyInstance;
let mockDecodePubKey: jest.SpyInstance;
let mockVerifyFIDOU2F: jest.SpyInstance;

beforeEach(() => {
  mockDecodeAttestation = jest.spyOn(decodeAttestationObject, 'default');
  mockDecodeClientData = jest.spyOn(decodeClientDataJSON, 'default');
  mockParseAuthData = jest.spyOn(parseAuthenticatorData, 'default');
  mockDecodePubKey = jest.spyOn(decodeCredentialPublicKey, 'default');
  mockVerifyFIDOU2F = jest.spyOn(verifyFIDOU2F, 'default');
});

afterEach(() => {
  mockDecodeAttestation.mockRestore();
  mockDecodeClientData.mockRestore();
  mockParseAuthData.mockRestore();
  mockDecodePubKey.mockRestore();
  mockVerifyFIDOU2F.mockRestore();
});

test('should verify FIDO U2F attestation', () => {
  const verification = verifyAttestationResponse({
    credential: attestationFIDOU2F,
    expectedChallenge: attestationFIDOU2FChallenge,
    expectedOrigin: 'https://dev.dontneeda.pw',
    expectedRPID: 'dev.dontneeda.pw',
  });

  expect(verification.verified).toEqual(true);
  expect(verification.authenticatorInfo?.fmt).toEqual('fido-u2f');
  expect(verification.authenticatorInfo?.counter).toEqual(0);
  expect(verification.authenticatorInfo?.base64PublicKey).toEqual(
    'BMiRyw5pUoMhBjCrcQND6lJPaRHA0f-XWcKBb5ZwWk1eFJu6aan4o7epl6qa9n9T-6KsIMvZE2PcTnLj8rN58is',
  );
  expect(verification.authenticatorInfo?.base64CredentialID).toEqual(
    'VHzbxaYaJu2P8m1Y2iHn2gRNHrgK0iYbn9E978L3Qi7Q-chFeicIHwYCRophz5lth2nCgEVKcgWirxlgidgbUQ',
  );
});

test('should verify Packed (EC2) attestation', () => {
  const verification = verifyAttestationResponse({
    credential: attestationPacked,
    expectedChallenge: attestationPackedChallenge,
    expectedOrigin: 'https://dev.dontneeda.pw',
    expectedRPID: 'dev.dontneeda.pw',
  });

  expect(verification.verified).toEqual(true);
  expect(verification.authenticatorInfo?.fmt).toEqual('packed');
  expect(verification.authenticatorInfo?.counter).toEqual(1589874425);
  expect(verification.authenticatorInfo?.base64PublicKey).toEqual(
    'BEoxVVqK-oIGmqoDEyO4KjmMx5R2HeMM4LQQXh8sE01PtzuuoMN5fWnAIuuXdlfshOGu1k3ApBUtDJ8eKiuo_6c',
  );
  expect(verification.authenticatorInfo?.base64CredentialID).toEqual(
    'AYThY1csINY4JrbHyGmqTl1nL_F1zjAF3hSAIngz8kAcjugmAMNVvxZRwqpEH-bNHHAIv291OX5ko9eDf_5mu3U' +
      'B2BvsScr2K-ppM4owOpGsqwg5tZglqqmxIm1Q',
  );
});

test('should verify Packed (X5C) attestation', () => {
  const verification = verifyAttestationResponse({
    credential: attestationPackedX5C,
    expectedChallenge: attestationPackedX5CChallenge,
    expectedOrigin: 'https://dev.dontneeda.pw',
    expectedRPID: 'dev.dontneeda.pw',
  });

  expect(verification.verified).toEqual(true);
  expect(verification.authenticatorInfo?.fmt).toEqual('packed');
  expect(verification.authenticatorInfo?.counter).toEqual(28);
  expect(verification.authenticatorInfo?.base64PublicKey).toEqual(
    'BGwlsYCNyRb4AD9cyTw6cH5VS-uzflmmO1UldGGe9eIavadzKD8p6wKLjgYfxRxldjCMGRV0YyM13osWbKIPrF8',
  );
  expect(verification.authenticatorInfo?.base64CredentialID).toEqual(
    '4rrvMciHCkdLQ2HghazIp1sMc8TmV8W8RgoX-x8tqV_1AmlqWACqUK8mBGLandr-htduQKPzgb2yWxOFV56Tlg',
  );
});

test('should verify None attestation', () => {
  const verification = verifyAttestationResponse({
    credential: attestationNone,
    expectedChallenge: attestationNoneChallenge,
    expectedOrigin: 'https://dev.dontneeda.pw',
    expectedRPID: 'dev.dontneeda.pw',
  });

  expect(verification.verified).toEqual(true);
  expect(verification.authenticatorInfo?.fmt).toEqual('none');
  expect(verification.authenticatorInfo?.counter).toEqual(0);
  expect(verification.authenticatorInfo?.base64PublicKey).toEqual(
    'BD5PQTZQQg6haZFQWFzqfAOyQ_ENsMH8xxQ4GRiNPsqrU8IVUOV8qpgk_Jh-OTaLuZL52KdX1fTht07X4DiQPow',
  );
  expect(verification.authenticatorInfo?.base64CredentialID).toEqual(
    'AdKXJEch1aV5Wo7bj7qLHskVY4OoNaj9qu8TPdJ7kSAgUeRxWNngXlcNIGt4gexZGKVGcqZpqqWordXb_he1izY',
  );
});

test('should throw when response challenge is not expected value', () => {
  expect(() => {
    verifyAttestationResponse({
      credential: attestationNone,
      expectedChallenge: 'shouldhavebeenthisvalue',
      expectedOrigin: 'https://dev.dontneeda.pw',
      expectedRPID: 'dev.dontneeda.pw',
    });
  }).toThrow(/attestation challenge/i);
});

test('should throw when response origin is not expected value', () => {
  expect(() => {
    verifyAttestationResponse({
      credential: attestationNone,
      expectedChallenge: attestationNoneChallenge,
      expectedOrigin: 'https://different.address',
      expectedRPID: 'dev.dontneeda.pw',
    });
  }).toThrow(/attestation origin/i);
});

test('should throw when attestation type is not webauthn.create', () => {
  const origin = 'https://dev.dontneeda.pw';
  const challenge = attestationNoneChallenge;

  // @ts-ignore 2345
  mockDecodeClientData.mockReturnValue({
    origin,
    type: 'webauthn.badtype',
    challenge: attestationNoneChallenge,
  });

  expect(() => {
    verifyAttestationResponse({
      credential: attestationNone,
      expectedChallenge: challenge,
      expectedOrigin: origin,
      expectedRPID: 'dev.dontneeda.pw',
    });
  }).toThrow(/attestation type/i);
});

test('should throw if an unexpected attestation format is specified', () => {
  const fmt = 'fizzbuzz';

  const realAtteObj = decodeAttestationObject.default(attestationNone.response.attestationObject);

  mockDecodeAttestation.mockReturnValue({
    ...realAtteObj,
    // @ts-ignore 2322
    fmt,
  });

  expect(() => {
    verifyAttestationResponse({
      credential: attestationNone,
      expectedChallenge: attestationNoneChallenge,
      expectedOrigin: 'https://dev.dontneeda.pw',
      expectedRPID: 'dev.dontneeda.pw',
    });
  }).toThrow(/unsupported attestation format/i);
});

test('should throw error if assertion RP ID is unexpected value', () => {
  const { authData } = decodeAttestationObject.default(attestationNone.response.attestationObject);
  const actualAuthData = parseAuthenticatorData.default(authData);

  mockParseAuthData.mockReturnValue({
    ...actualAuthData,
    rpIdHash: toHash(Buffer.from('bad.url', 'ascii')),
  });

  expect(() => {
    verifyAttestationResponse({
      credential: attestationNone,
      expectedChallenge: attestationNoneChallenge,
      expectedOrigin: 'https://dev.dontneeda.pw',
      expectedRPID: 'dev.dontneeda.pw',
    });
  }).toThrow(/rp id/i);
});

test('should throw error if user was not present', () => {
  mockParseAuthData.mockReturnValue({
    rpIdHash: toHash(Buffer.from('dev.dontneeda.pw', 'ascii')),
    flags: {
      up: false,
    },
  });

  expect(() => {
    verifyAttestationResponse({
      credential: attestationNone,
      expectedChallenge: attestationNoneChallenge,
      expectedOrigin: 'https://dev.dontneeda.pw',
      expectedRPID: 'dev.dontneeda.pw',
    });
  }).toThrow(/not present/i);
});

test('should throw if the authenticator does not give back credential ID', () => {
  mockParseAuthData.mockReturnValue({
    rpIdHash: toHash(Buffer.from('dev.dontneeda.pw', 'ascii')),
    flags: {
      up: true,
    },
    credentialID: undefined,
  });

  expect(() => {
    verifyAttestationResponse({
      credential: attestationNone,
      expectedChallenge: attestationNoneChallenge,
      expectedOrigin: 'https://dev.dontneeda.pw',
      expectedRPID: 'dev.dontneeda.pw',
    });
  }).toThrow(/credential id/i);
});

test('should throw if the authenticator does not give back credential public key', () => {
  mockParseAuthData.mockReturnValue({
    rpIdHash: toHash(Buffer.from('dev.dontneeda.pw', 'ascii')),
    flags: {
      up: true,
    },
    credentialID: 'aaa',
    credentialPublicKey: undefined,
  });

  expect(() => {
    verifyAttestationResponse({
      credential: attestationNone,
      expectedChallenge: attestationNoneChallenge,
      expectedOrigin: 'https://dev.dontneeda.pw',
      expectedRPID: 'dev.dontneeda.pw',
    });
  }).toThrow(/public key/i);
});

test('should throw error if no alg is specified in public key', () => {
  mockDecodePubKey.mockReturnValue({
    get: () => undefined,
    credentialID: '',
    credentialPublicKey: '',
  });

  expect(() => {
    verifyAttestationResponse({
      credential: attestationNone,
      expectedChallenge: attestationNoneChallenge,
      expectedOrigin: 'https://dev.dontneeda.pw',
      expectedRPID: 'dev.dontneeda.pw',
    });
  }).toThrow(/missing alg/i);
});

test('should throw error if unsupported alg is used', () => {
  mockDecodePubKey.mockReturnValue({
    get: () => -999,
    credentialID: '',
    credentialPublicKey: '',
  });

  expect(() => {
    verifyAttestationResponse({
      credential: attestationNone,
      expectedChallenge: attestationNoneChallenge,
      expectedOrigin: 'https://dev.dontneeda.pw',
      expectedRPID: 'dev.dontneeda.pw',
    });
  }).toThrow(/unexpected public key/i);
});

test('should not include authenticator info if not verified', () => {
  mockVerifyFIDOU2F.mockReturnValue(false);

  const verification = verifyAttestationResponse({
    credential: attestationFIDOU2F,
    expectedChallenge: attestationFIDOU2FChallenge,
    expectedOrigin: 'https://dev.dontneeda.pw',
    expectedRPID: 'dev.dontneeda.pw',
  });

  expect(verification.verified).toBe(false);
  expect(verification.authenticatorInfo).toBeUndefined();
});

test('should throw an error if user verification is required but user was not verified', () => {
  mockParseAuthData.mockReturnValue({
    rpIdHash: toHash(Buffer.from('dev.dontneeda.pw', 'ascii')),
    flags: {
      up: true,
      uv: false,
    },
  });

  expect(() => {
    verifyAttestationResponse({
      credential: attestationFIDOU2F,
      expectedChallenge: attestationFIDOU2FChallenge,
      expectedOrigin: 'https://dev.dontneeda.pw',
      expectedRPID: 'dev.dontneeda.pw',
      requireUserVerification: true,
    });
  }).toThrow(/user could not be verified/i);
});

/**
 * Various Attestations Below
 */

const attestationFIDOU2F = {
  id: 'VHzbxaYaJu2P8m1Y2iHn2gRNHrgK0iYbn9E978L3Qi7Q-chFeicIHwYCRophz5lth2nCgEVKcgWirxlgidgbUQ',
  rawId: 'VHzbxaYaJu2P8m1Y2iHn2gRNHrgK0iYbn9E978L3Qi7Q-chFeicIHwYCRophz5lth2nCgEVKcgWirxlgidgbUQ',
  response: {
    attestationObject:
      'o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgRYUftNUmhT0VWTZmIgDmrOoP26Pcre-kL3DLnCrXbegCIQCOu_x5gqp-Rej76zeBuXlk8e7J-9WM_i-wZmCIbIgCGmN4NWOBWQLBMIICvTCCAaWgAwIBAgIEKudiYzANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgNzE5ODA3MDc1MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKgOGXmBD2Z4R_xCqJVRXhL8Jr45rHjsyFykhb1USGozZENOZ3cdovf5Ke8fj2rxi5tJGn_VnW4_6iQzKdIaeP6NsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjEwEwYLKwYBBAGC5RwCAQEEBAMCBDAwIQYLKwYBBAGC5RwBAQQEEgQQbUS6m_bsLkm5MAyP6SDLczAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQByV9A83MPhFWmEkNb4DvlbUwcjc9nmRzJjKxHc3HeK7GvVkm0H4XucVDB4jeMvTke0WHb_jFUiApvpOHh5VyMx5ydwFoKKcRs5x0_WwSWL0eTZ5WbVcHkDR9pSNcA_D_5AsUKOBcbpF5nkdVRxaQHuuIuwV4k1iK2IqtMNcU8vL6w21U261xCcWwJ6sMq4zzVO8QCKCQhsoIaWrwz828GDmPzfAjFsJiLJXuYivdHACkeJ5KHMt0mjVLpfJ2BCML7_rgbmvwL7wBW80VHfNdcKmKjkLcpEiPzwcQQhiN_qHV90t-p4iyr5xRSpurlP5zic2hlRkLKxMH2_kRjhqSn4aGF1dGhEYXRhWMQ93EcQ6cCIsinbqJ1WMiC7Ofcimv9GWwplaxr7mor4oEEAAAAAAAAAAAAAAAAAAAAAAAAAAABAVHzbxaYaJu2P8m1Y2iHn2gRNHrgK0iYbn9E978L3Qi7Q-chFeicIHwYCRophz5lth2nCgEVKcgWirxlgidgbUaUBAgMmIAEhWCDIkcsOaVKDIQYwq3EDQ-pST2kRwNH_l1nCgW-WcFpNXiJYIBSbummp-KO3qZeqmvZ_U_uirCDL2RNj3E5y4_KzefIr',
    clientDataJSON:
      'eyJjaGFsbGVuZ2UiOiJkRzkwWVd4c2VWVnVhWEYxWlZaaGJIVmxSWFpsY25sQmRIUmxjM1JoZEdsdmJnIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9kZXYuZG9udG5lZWRhLnB3IiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9',
  },
  getClientExtensionResults: () => ({}),
  type: 'public-key',
};
const attestationFIDOU2FChallenge = 'totallyUniqueValueEveryAttestation';

const attestationPacked = {
  id: 'bbb',
  rawId: 'bbb',
  response: {
    attestationObject:
      'o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIhANvrPZMUFrl_rvlgR' +
      'qz6lCPlF6B4y885FYUCCrhrzAYXAiAb4dQKXbP3IimsTTadkwXQlrRVdxzlbmPXt847-Oh6r2hhdXRoRGF0YVjhP' +
      'dxHEOnAiLIp26idVjIguzn3Ipr_RlsKZWsa-5qK-KBFXsOO-a3OAAI1vMYKZIsLJfHwVQMAXQGE4WNXLCDWOCa2x' +
      '8hpqk5dZy_xdc4wBd4UgCJ4M_JAHI7oJgDDVb8WUcKqRB_mzRxwCL9vdTl-ZKPXg3_-Zrt1Adgb7EnK9ivqaTOKM' +
      'DqRrKsIObWYJaqpsSJtUKUBAgMmIAEhWCBKMVVaivqCBpqqAxMjuCo5jMeUdh3jDOC0EF4fLBNNTyJYILc7rqDDe' +
      'X1pwCLrl3ZX7IThrtZNwKQVLQyfHiorqP-n',
    clientDataJSON:
      'eyJjaGFsbGVuZ2UiOiJjelpRU1dKQ2JsQlFibkpIVGxOQ2VFNWtkRVJ5VkRkVmNsWlpT' +
      'a3M1U0UwIiwib3JpZ2luIjoiaHR0cHM6Ly9kZXYuZG9udG5lZWRhLnB3IiwidHlwZSI6IndlYmF1dGhuLmNyZWF0' +
      'ZSJ9',
  },
  getClientExtensionResults: () => ({}),
  type: 'public-key',
};
const attestationPackedChallenge = 's6PIbBnPPnrGNSBxNdtDrT7UrVYJK9HM';

const attestationPackedX5C = {
  // TODO: Grab these from another iPhone attestation
  id: 'aaa',
  rawId: 'aaa',
  response: {
    attestationObject:
      'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIhAIMt_hGMtdgpIVIwMOeKK' +
      'w0IkUUFkXSY8arKh3Q0c5QQAiB9Sv9JavAEmppeH_XkZjB7TFM3jfxsgl97iIkvuJOUImN4NWOBWQLBMIICvTCCAaWgA' +
      'wIBAgIEKudiYzANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwM' +
      'DYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1Ymljb' +
      'yBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpY' +
      'WwgNzE5ODA3MDc1MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKgOGXmBD2Z4R_xCqJVRXhL8Jr45rHjsyFykhb1USG' +
      'ozZENOZ3cdovf5Ke8fj2rxi5tJGn_VnW4_6iQzKdIaeP6NsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4M' +
      'i4xLjEwEwYLKwYBBAGC5RwCAQEEBAMCBDAwIQYLKwYBBAGC5RwBAQQEEgQQbUS6m_bsLkm5MAyP6SDLczAMBgNVHRMBA' +
      'f8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQByV9A83MPhFWmEkNb4DvlbUwcjc9nmRzJjKxHc3HeK7GvVkm0H4XucVDB4j' +
      'eMvTke0WHb_jFUiApvpOHh5VyMx5ydwFoKKcRs5x0_WwSWL0eTZ5WbVcHkDR9pSNcA_D_5AsUKOBcbpF5nkdVRxaQHuu' +
      'IuwV4k1iK2IqtMNcU8vL6w21U261xCcWwJ6sMq4zzVO8QCKCQhsoIaWrwz828GDmPzfAjFsJiLJXuYivdHACkeJ5KHMt' +
      '0mjVLpfJ2BCML7_rgbmvwL7wBW80VHfNdcKmKjkLcpEiPzwcQQhiN_qHV90t-p4iyr5xRSpurlP5zic2hlRkLKxMH2_k' +
      'RjhqSn4aGF1dGhEYXRhWMQ93EcQ6cCIsinbqJ1WMiC7Ofcimv9GWwplaxr7mor4oEEAAAAcbUS6m_bsLkm5MAyP6SDLc' +
      'wBA4rrvMciHCkdLQ2HghazIp1sMc8TmV8W8RgoX-x8tqV_1AmlqWACqUK8mBGLandr-htduQKPzgb2yWxOFV56TlqUBA' +
      'gMmIAEhWCBsJbGAjckW-AA_XMk8OnB-VUvrs35ZpjtVJXRhnvXiGiJYIL2ncyg_KesCi44GH8UcZXYwjBkVdGMjNd6LF' +
      'myiD6xf',
    clientDataJSON:
      'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZEc5MFlXeHNlVlZ1YVhG' +
      'MVpWWmhiSFZsUlhabGNubFVhVzFsIiwib3JpZ2luIjoiaHR0cHM6Ly9kZXYuZG9udG5lZWRhLnB3In0=',
  },
  getClientExtensionResults: () => ({}),
  type: 'public-key',
};
const attestationPackedX5CChallenge = 'totallyUniqueValueEveryTime';

const attestationNone = {
  id: 'AdKXJEch1aV5Wo7bj7qLHskVY4OoNaj9qu8TPdJ7kSAgUeRxWNngXlcNIGt4gexZGKVGcqZpqqWordXb_he1izY',
  rawId: 'AdKXJEch1aV5Wo7bj7qLHskVY4OoNaj9qu8TPdJ7kSAgUeRxWNngXlcNIGt4gexZGKVGcqZpqqWordXb_he1izY',
  response: {
    attestationObject:
      'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjFPdxHEOnAiLIp26idVjIguzn3I' +
      'pr_RlsKZWsa-5qK-KBFAAAAAAAAAAAAAAAAAAAAAAAAAAAAQQHSlyRHIdWleVqO24-6ix7JFWODqDWo_arvEz3Se' +
      '5EgIFHkcVjZ4F5XDSBreIHsWRilRnKmaaqlqK3V2_4XtYs2pQECAyYgASFYID5PQTZQQg6haZFQWFzqfAOyQ_ENs' +
      'MH8xxQ4GRiNPsqrIlggU8IVUOV8qpgk_Jh-OTaLuZL52KdX1fTht07X4DiQPow',
    clientDataJSON:
      'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiYUVWalkxQlhkWHBw' +
      'VURBd1NEQndOV2Q0YURKZmRUVmZVRU0wVG1WWloyUSIsIm9yaWdpbiI6Imh0dHBzOlwvXC9kZXYuZG9udG5lZWRh' +
      'LnB3IiwiYW5kcm9pZFBhY2thZ2VOYW1lIjoib3JnLm1vemlsbGEuZmlyZWZveCJ9',
  },
  getClientExtensionResults: () => ({}),
  type: 'public-key',
};
const attestationNoneChallenge = 'hEccPWuziP00H0p5gxh2_u5_PC4NeYgd';
