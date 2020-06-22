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

test('should validate TPM RSA response (SHA256)', () => {
  jest.spyOn(base64url, 'encode').mockReturnValueOnce(attestationTPMRSAChallenge);
  const verification = verifyAttestationResponse({
    credential: attestationTPMRSA,
    expectedChallenge: attestationTPMRSAChallenge,
    expectedOrigin: 'https://dev.dontneeda.pw',
    expectedRPID: 'dev.dontneeda.pw',
  });

  expect(verification.verified).toEqual(true);
  expect(verification.authenticatorInfo?.fmt).toEqual('tpm');
  expect(verification.authenticatorInfo?.counter).toEqual(125);
  expect(verification.authenticatorInfo?.base64PublicKey).toEqual('BAEAAQ');
  expect(verification.authenticatorInfo?.base64CredentialID).toEqual(
    '_7EdkyBmTxeN80POW2GJtrtlz7GkSjHJkOw-Zr6AQU0',
  );
});

test('should validate TPM RSA response (SHA1)', () => {
  jest.spyOn(base64url, 'encode').mockReturnValueOnce(attestationTPMRSASHA1Challenge);
  const verification = verifyAttestationResponse({
    credential: attestationTPMRSASHA1,
    expectedChallenge: attestationTPMRSASHA1Challenge,
    expectedOrigin: 'https://dev.dontneeda.pw',
    expectedRPID: 'dev.dontneeda.pw',
  });

  expect(verification.verified).toEqual(true);
  expect(verification.authenticatorInfo?.fmt).toEqual('tpm');
  expect(verification.authenticatorInfo?.counter).toEqual(22);
  expect(verification.authenticatorInfo?.base64PublicKey).toEqual('BAEAAQ');
  expect(verification.authenticatorInfo?.base64CredentialID).toEqual(
    'lSiFY4VF1uvmq7gZ-85Snh5WAKCRspf0LrkxqSl41vg',
  );
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

const attestationTPMRSA = {
  id: '_7EdkyBmTxeN80POW2GJtrtlz7GkSjHJkOw-Zr6AQU0',
  rawId: '_7EdkyBmTxeN80POW2GJtrtlz7GkSjHJkOw-Zr6AQU0',
  response: {
    attestationObject:
      'o2NmbXRjdHBtZ2F0dFN0bXSmY2FsZzkBAGNzaWdZAQBYVbI753oaC99JbqEy0yIoY5GaWVRQ4Wiuy6736CmMT3I9m27wBh_Xzfm1fMzCUHJOYpzrk0NDi1bY1atbH7LiZW8WbzUgUhGU1EUVY86i_TTSFeHg3afID7myZMjNztIOD8uP8xauBjbr7TjxWC2iyK04vlHmfT5582llEbHlgC_wPDMMMrSkE4EDOONSe50NSn3zgHc8ixSLqoQDDDugy4lvsFa8K-r6d7HlCrrvH2kKBY-jPx7I-qwkAcZjR6xcFQ58mBlJkTxLYp4Gxe3mD5EitcQtfMZvHvf4q3v6-t3mi48vyHOwkC2Qkux96j3o_AgrBVnNp-8UHb1bca0zY3ZlcmMyLjBjeDVjglkEhzCCBIMwggNroAMCAQICDwRxy48LtqgQLIabBuW6OTANBgkqhkiG9w0BAQsFADBBMT8wPQYDVQQDEzZOQ1UtTlRDLUtFWUlELUZGOTkwMzM4RTE4NzA3OUE2Q0Q2QTAzQURDNTcyMzc0NDVGNkE0OUEwHhcNMTgwMjAxMDAwMDAwWhcNMjUwMTMxMjM1OTU5WjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9U6kJlP8LOA27lOkrWKAFgsz-nrUTDDA4KNI_uVPqulTY7KvyBgvIb4L7UmGVQ5_SszGUBfgh4_mRvHMYnJEVut_MHmni2yz1ane-bXEt7OeJ3PFXcr_1xOzSPTnpOE3XH5-iABDMqcFtViFOr3hF9uosD3vx6HvfP02iZZTrJZm0dwYQE-6UlTSaf3fV_pBRRg4oL3ychh1akw1zFUktT933HVUjD29OTkYzQ-0TjilmMUYx4Tyg3QYVnvl5dmrDkmJXQ9Ip69D6JEZHxCxN4ilUf9Ih8IB0mLqIgILqh6mMdgx9ZaaaHNbAAjJAeKS_3H2EvnnmpeZRPuSkQy8YQIDAQABo4IBtzCCAbMwDgYDVR0PAQH_BAQDAgeAMAwGA1UdEwEB_wQCMAAwewYDVR0gAQH_BHEwbzBtBgkrBgEEAYI3FR8wYDBeBggrBgEFBQcCAjBSHlAARgBBAEsARQAgAEYASQBEAE8AIABUAEMAUABBACAAVAByAHUAcwB0AGUAZAAgAFAAbABhAHQAZgBvAHIAbQAgAEkAZABlAG4AdABpAHQAeTAQBgNVHSUECTAHBgVngQUIAzBKBgNVHREBAf8EQDA-pDwwOjE4MA4GBWeBBQIDDAVpZDoxMzAQBgVngQUCAgwHTlBDVDZ4eDAUBgVngQUCAQwLaWQ6RkZGRkYxRDAwHwYDVR0jBBgwFoAUdOhwbuNi8U8_KoCvb3uGHTvHco0wHQYDVR0OBBYEFJZf1lKHB0sYt1vaRbqjWh8xfCPoMHgGCCsGAQUFBwEBBGwwajBoBggrBgEFBQcwAoZcaHR0cHM6Ly9maWRvYWxsaWFuY2UuY28ubnovdHBtcGtpL05DVS1OVEMtS0VZSUQtRkY5OTAzMzhFMTg3MDc5QTZDRDZBMDNBREM1NzIzNzQ0NUY2QTQ5QS5jcnQwDQYJKoZIhvcNAQELBQADggEBACf7gOeDfFGKXSVguQGIMym-d8Hm7AvXaVZE6KD64n86jOA1IHb5kADTYbLuYRTzEqA6t9YpWAQSNp2b6FmPsX2nqTAw2Pcp24fAuPmWInJI4ZO1bEQ1FyxivCrpgkIRXSegM6oKJXjW92vMpY9Gk2eOsHFOWAT4nhZgDF0wPSR1kZFppfsOBV4cOJZWh4EfiyTdlIlHZno6T5XzCldIELwTNdCNaTEHK7VmbQZ2J8hIQRKIs23i8Gz45t1eAQmhEJpS_fcr2Bj3IljSKmgZvOCFLk4jI4cQU3cIYXEyZmnEGf651k3Wmt3voJL9pZwJ_eXIfuHccsuh0qW5AVE7tQJZBgUwggYBMIID6aADAgECAg8EV2dM14jMuwRaKXATKH8wDQYJKoZIhvcNAQELBQAwgb8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMQwwCgYDVQQLDANDV0cxNjA0BgNVBAMMLUZJRE8gRmFrZSBUUE0gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxODExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzAeFw0xNzAyMDEwMDAwMDBaFw0zNTAxMzEyMzU5NTlaMEExPzA9BgNVBAMTNk5DVS1OVEMtS0VZSUQtRkY5OTAzMzhFMTg3MDc5QTZDRDZBMDNBREM1NzIzNzQ0NUY2QTQ5QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANc-c30RpQd-_LCoiLJbXz3t_vqciOIovwjez79_DtVgi8G9Ph-tPL-lC0ueFGBMSPcKd_RDdSFe2QCYQd9e0DtiFxra-uWGa0olI1hHI7bK2GzNAZSTKEbwgqpf8vXMQ-7SPajg6PfxSOLH_Nj2yd6tkNkUSdlGtWfY8XGB3n-q--nt3UHdUQWEtgUoTe5abBXsG7MQSuTNoad3v6vk-tLd0W44ivM6pbFqFUHchx8mGLApCpjlVXrfROaCoc9E91hG9B-WNvekJ0dM6kJ658Hy7yscQ6JdqIEolYojCtWaWNmwcfv--OE1Ax_4Ub24gl3hpB9EOcBCzpb4UFmLYUECAwEAAaOCAXUwggFxMAsGA1UdDwQEAwIBhjAWBgNVHSAEDzANMAsGCSsGAQQBgjcVHzAbBgNVHSUEFDASBgkrBgEEAYI3FSQGBWeBBQgDMBIGA1UdEwEB_wQIMAYBAf8CAQAwHQYDVR0OBBYEFHTocG7jYvFPPyqAr297hh07x3KNMB8GA1UdIwQYMBaAFEMRFpma7p1QN8JP_uJbFckJMz8yMGgGA1UdHwRhMF8wXaBboFmGV2h0dHBzOi8vZmlkb2FsbGlhbmNlLmNvLm56L3RwbXBraS9jcmwvRklETyBGYWtlIFRQTSBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDE4LmNybDBvBggrBgEFBQcBAQRjMGEwXwYIKwYBBQUHMAKGU2h0dHBzOi8vZmlkb2FsbGlhbmNlLmNvLm56L3RwbXBraS9GSURPIEZha2UgVFBNIFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTguY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQBI6GeuxIkeKcmRmFQnkPnkvSybRIJEkzWKa2f00vdBygxtzpkXF2WMHbvuMU3_K3WMFzg2xkSPjM3x_-UxOWGYgVIq8fXUdy2NhmLz4tPI65_nQXpS22rzmXFzsj4x9yS0JF2NnW5xm-O8UdckFdwIZx4Ew_zA-rIF3hqbY4Ejz2AdsbvHJo-WTpu-wWDbBQyR19eqNyYZ6vf9K8DB2JZviIDXdOpkuOJLA40MKMlnhv5K4BZs7mDZIaPzNA_MrcH3_dYXq4tIoGu5Pr1ZNCQ--93XYG1eRbvCgSDYUCRza5AgBGCIhmx2-tqLYeCd9qdy4O9R9c9qRjEThbjnGStYZ0DuB6VCaH1WjiRqyq4VNi9cv15-RoC4zswWwuHee97AAJ_Tx29w6S4Kw9DQR6A0vtw_OHLuOkGH63ns0DACf_h1MvsAMnXXX0Q0P8IpNdBQGvLvrRtRdBNx06NHY1HGZOZ9PdJ6J4mnroB2ln3cMGZG9kyRv2vbwq6sCrYZVYjo3tf4MUtkEY4FijoYbMEDK7VlbTiDPnobhkxI1-bz5DTFnR3IfVybYAeGrBCKSg2UUTPvVgM3WZ-oGlP8W9dg1347hqgxP0vLgDM6cV7rhaFC_ZAf2Et9KLRZSj7lNpJWxHxPyz9mM4w3qFwdgWKwlXl3OQtJRT4Kbs6r3gzB5WdwdWJBcmVhWQE2AAEACwAGBHIAIJ3_y_NsODrmmfuYaNxty4nXFTiEvigDkiwSQVi_rSKuABAAEAgAAAAAAAEAzVqoi5l9Q-VS4lXtYt204eP4Wpp2-xDEJYOeCDuC7816a-zywokLSPK72YDYVynHKMfScNk1zSwQJNaU_TjFG7dfKj8TWi_PWlfQl2_RbjlrG67gHvgVqgERemvQ4UnRVRv_71LT8A_CFUO65FYx-9k4LoeKnFP08zwYjNunhKgW0VmC1lJrAgNDAw21-07nyIz427Sg_bDBh-yySy68J_FM1XAymN3wCUyNyKDZuC4wwbF_HL6RDq9AxfM-X2a4wDvXFFZzlPg5toGXjmKpicEKUTNTOvye9fBxC2tVa3CcXLcO-rQo-i-EGvGpBkDgWmcfJ6IfvWZpEWZPHnklfWhjZXJ0SW5mb1it_1RDR4AXACIACxHmjtRNtTcuFCluL4Ssx4OYdRiBkh4w_CKgb4tzx5RTACCuCPDI20UzFVupLTuRN-sXjXVCLhkADeWtymv_9ZrDsgAAAAFHcBdIVWl7S8aFYKUBc375jTRWVfsAIgAL_r1sUJScBKEZNlz-OxQhImOhmJBTxzPYu3T1ASrW5RkAIgAL9LnwBOvgl5V8_SFE7ww1EbaZSL9a-Gagnodd_fPuIBRoYXV0aERhdGFZAWc93EcQ6cCIsinbqJ1WMiC7Ofcimv9GWwplaxr7mor4oEEAAAB9p9bZOooNEeialKbPcQcvcwAg_7EdkyBmTxeN80POW2GJtrtlz7GkSjHJkOw-Zr6AQU2kAQMDOQEAIFkBAM1aqIuZfUPlUuJV7WLdtOHj-FqadvsQxCWDngg7gu_Nemvs8sKJC0jyu9mA2FcpxyjH0nDZNc0sECTWlP04xRu3Xyo_E1ovz1pX0Jdv0W45axuu4B74FaoBEXpr0OFJ0VUb_-9S0_APwhVDuuRWMfvZOC6HipxT9PM8GIzbp4SoFtFZgtZSawIDQwMNtftO58iM-Nu0oP2wwYfssksuvCfxTNVwMpjd8AlMjcig2bguMMGxfxy-kQ6vQMXzPl9muMA71xRWc5T4ObaBl45iqYnBClEzUzr8nvXwcQtrVWtwnFy3Dvq0KPovhBrxqQZA4FpnHyeiH71maRFmTx55JX0hQwEAAQ',
    clientDataJSON:
      'eyJvcmlnaW4iOiJodHRwczovL2Rldi5kb250bmVlZGEucHciLCJjaGFsbGVuZ2UiOiI2ZGViMWNlNi0zM2Q0LTQ4MDYtOTM2Ni1lMDYzMWQ0NmE2NTIiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0',
  },
  type: 'public-key',
};
const attestationTPMRSAChallenge = '6deb1ce6-33d4-4806-9366-e0631d46a652';

const attestationTPMRSASHA1 = {
  id: 'lSiFY4VF1uvmq7gZ-85Snh5WAKCRspf0LrkxqSl41vg',
  rawId: 'lSiFY4VF1uvmq7gZ-85Snh5WAKCRspf0LrkxqSl41vg',
  response: {
    attestationObject:
      'o2NmbXRjdHBtZ2F0dFN0bXSmY2FsZzn__mNzaWdZAQCYUsHcCYDXPM4Q8MAAuR6WfgKb35J2OXP7RN13yVYQ53ZkoOFY0RbTjqltOL2uTdTbTFAYrNckf_rEFIcS3TiQo55Ok9qlZ00zW-xjB4B3Yrd0OGaV0cxeF-N_8uogpPf1f1cKTDzwwAhYzqsxgZ9mFI_wlwJelXbbkQCqAtgESRtzNQePPnFxu9G5vgVHQnEWAKWdMcS7h6_-QJ6iZ0_04HDccmVvSNZTcuOdgfjaGh_ZceGdG28FJOlvb5Up2vBZEyfyYdnmqLZy-QF8sFhdbwTNw2QB0T1qwEHFvrrV98RqGNBmbRPLdDNVy0nH2wapTfx34H7ElwGR-Xj632LKY3ZlcmMyLjBjeDVjglkEhzCCBIMwggNroAMCAQICDwTaXX5caaES4LH4S8iygTANBgkqhkiG9w0BAQsFADBBMT8wPQYDVQQDEzZOQ1UtTlRDLUtFWUlELUZGOTkwMzM4RTE4NzA3OUE2Q0Q2QTAzQURDNTcyMzc0NDVGNkE0OUEwHhcNMTgwMjAxMDAwMDAwWhcNMjUwMTMxMjM1OTU5WjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmveqwQ1iNmuOI-2JMOvwfRaho9Sk8FdWF8CqsJnfxQarLmvsN-UEz1MpNfW9AXO1HRWQBIDMzf5WT0ZnX0wGaEvTztofdlEmNNb-gFfYOQnmHDm_reGZd3jEAda-iMJMvak9GG2BcefKeHAvTPpVw3sTigOCGxr4YKFX9dvh4sn_41PymogO-ilK4fg2aqDm6cH9UWa06LMknyGyHX8w3wWhxugfeJCx29hhLAZvM3UBXP-L8tYV_UAmYcWJ5b8don_2tvbxfVBoOjEzGEU2XrQkla9bUxxpM-iiRufQ6bXWTSQe8TRCfg3hb-cQK0V5j7iHrR6LyNCRvtgwE1HNzQIDAQABo4IBtzCCAbMwDgYDVR0PAQH_BAQDAgeAMAwGA1UdEwEB_wQCMAAwewYDVR0gAQH_BHEwbzBtBgkrBgEEAYI3FR8wYDBeBggrBgEFBQcCAjBSHlAARgBBAEsARQAgAEYASQBEAE8AIABUAEMAUABBACAAVAByAHUAcwB0AGUAZAAgAFAAbABhAHQAZgBvAHIAbQAgAEkAZABlAG4AdABpAHQAeTAQBgNVHSUECTAHBgVngQUIAzBKBgNVHREBAf8EQDA-pDwwOjE4MA4GBWeBBQIDDAVpZDoxMzAQBgVngQUCAgwHTlBDVDZ4eDAUBgVngQUCAQwLaWQ6RkZGRkYxRDAwHwYDVR0jBBgwFoAUdOhwbuNi8U8_KoCvb3uGHTvHco0wHQYDVR0OBBYEFLZ8sxDFQbDACUEEyDnpSujjma69MHgGCCsGAQUFBwEBBGwwajBoBggrBgEFBQcwAoZcaHR0cHM6Ly9maWRvYWxsaWFuY2UuY28ubnovdHBtcGtpL05DVS1OVEMtS0VZSUQtRkY5OTAzMzhFMTg3MDc5QTZDRDZBMDNBREM1NzIzNzQ0NUY2QTQ5QS5jcnQwDQYJKoZIhvcNAQELBQADggEBAMdCK0CLUUpqMtnMkktm7NSWvC171YZaxibz29b4DL0EzfeID7gZUHBI41_EGC5uJo-31dMytLxPZoBEFBSYOU8saAZ1xcbBB5GgOpTbp1veXkNR9USC2PvYtVBic8Q1YKYeBTTLV7OAZqoyhP3cPTHa1OHy67bkt_4z7PxAP3sobvMFOCkOeJ0yJNMbXNgJ6vqIkXGdOB-SPnZZyBH33ShbTFYXYhwWho_0iivI38nSK3FrHJsxH0EKr5vXXAz08xkrtBIrLCtG42SHBgm7TdIhsEasdpjImhjZWYK4rC1HkPe6g2t5y1z43UhRdxNaFPCk4cERtiB7K_2Qtp2TC3RZBgUwggYBMIID6aADAgECAg8EV2dM14jMuwRaKXATKH8wDQYJKoZIhvcNAQELBQAwgb8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMQwwCgYDVQQLDANDV0cxNjA0BgNVBAMMLUZJRE8gRmFrZSBUUE0gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxODExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzAeFw0xNzAyMDEwMDAwMDBaFw0zNTAxMzEyMzU5NTlaMEExPzA9BgNVBAMTNk5DVS1OVEMtS0VZSUQtRkY5OTAzMzhFMTg3MDc5QTZDRDZBMDNBREM1NzIzNzQ0NUY2QTQ5QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANc-c30RpQd-_LCoiLJbXz3t_vqciOIovwjez79_DtVgi8G9Ph-tPL-lC0ueFGBMSPcKd_RDdSFe2QCYQd9e0DtiFxra-uWGa0olI1hHI7bK2GzNAZSTKEbwgqpf8vXMQ-7SPajg6PfxSOLH_Nj2yd6tkNkUSdlGtWfY8XGB3n-q--nt3UHdUQWEtgUoTe5abBXsG7MQSuTNoad3v6vk-tLd0W44ivM6pbFqFUHchx8mGLApCpjlVXrfROaCoc9E91hG9B-WNvekJ0dM6kJ658Hy7yscQ6JdqIEolYojCtWaWNmwcfv--OE1Ax_4Ub24gl3hpB9EOcBCzpb4UFmLYUECAwEAAaOCAXUwggFxMAsGA1UdDwQEAwIBhjAWBgNVHSAEDzANMAsGCSsGAQQBgjcVHzAbBgNVHSUEFDASBgkrBgEEAYI3FSQGBWeBBQgDMBIGA1UdEwEB_wQIMAYBAf8CAQAwHQYDVR0OBBYEFHTocG7jYvFPPyqAr297hh07x3KNMB8GA1UdIwQYMBaAFEMRFpma7p1QN8JP_uJbFckJMz8yMGgGA1UdHwRhMF8wXaBboFmGV2h0dHBzOi8vZmlkb2FsbGlhbmNlLmNvLm56L3RwbXBraS9jcmwvRklETyBGYWtlIFRQTSBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDE4LmNybDBvBggrBgEFBQcBAQRjMGEwXwYIKwYBBQUHMAKGU2h0dHBzOi8vZmlkb2FsbGlhbmNlLmNvLm56L3RwbXBraS9GSURPIEZha2UgVFBNIFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTguY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQBI6GeuxIkeKcmRmFQnkPnkvSybRIJEkzWKa2f00vdBygxtzpkXF2WMHbvuMU3_K3WMFzg2xkSPjM3x_-UxOWGYgVIq8fXUdy2NhmLz4tPI65_nQXpS22rzmXFzsj4x9yS0JF2NnW5xm-O8UdckFdwIZx4Ew_zA-rIF3hqbY4Ejz2AdsbvHJo-WTpu-wWDbBQyR19eqNyYZ6vf9K8DB2JZviIDXdOpkuOJLA40MKMlnhv5K4BZs7mDZIaPzNA_MrcH3_dYXq4tIoGu5Pr1ZNCQ--93XYG1eRbvCgSDYUCRza5AgBGCIhmx2-tqLYeCd9qdy4O9R9c9qRjEThbjnGStYZ0DuB6VCaH1WjiRqyq4VNi9cv15-RoC4zswWwuHee97AAJ_Tx29w6S4Kw9DQR6A0vtw_OHLuOkGH63ns0DACf_h1MvsAMnXXX0Q0P8IpNdBQGvLvrRtRdBNx06NHY1HGZOZ9PdJ6J4mnroB2ln3cMGZG9kyRv2vbwq6sCrYZVYjo3tf4MUtkEY4FijoYbMEDK7VlbTiDPnobhkxI1-bz5DTFnR3IfVybYAeGrBCKSg2UUTPvVgM3WZ-oGlP8W9dg1347hqgxP0vLgDM6cV7rhaFC_ZAf2Et9KLRZSj7lNpJWxHxPyz9mM4w3qFwdgWKwlXl3OQtJRT4Kbs6r3gzB5WdwdWJBcmVhWQE2AAEACwAGBHIAIJ3_y_NsODrmmfuYaNxty4nXFTiEvigDkiwSQVi_rSKuABAAEAgAAAAAAAEAv5ekb29pJ2ZbPeHVTbIYE2Q4aVuSKYyg6YAW1m8GGwD2ejOE95gYaycx_t306VPe6zLtf-ppoyv5Fseu3nDn12077wAluajegSuolJNTXNXDwxl4-h-mY22RY0OXQ6IPS-w9iIAVJURJvP8k7Q5Bz_hsk7pyql6DiSTVB8FgLsCsSqXwRBqU9pGZ9WtPESHQsg1wVXqi798JgKZ0eNvOr_vVqChiRUf9EIMCgHxeS2p0wVeCZa_NzwBMdMvoPMZOZSb-ycHrVOYxB8cBtDQ9xebwnFWuH4laCch2kIn9Y-phQoa0TdPLNOyefqpmW50sigak0fByrkEhsWjWTjwcUWhjZXJ0SW5mb1ih_1RDR4AXACIACxHmjtRNtTcuFCluL4Ssx4OYdRiBkh4w_CKgb4tzx5RTABTLU3QVcLKzb48EJS_2TX-_7E2TpgAAAAFHcBdIVWl7S8aFYKUBc375jTRWVfsAIgALp3lm-UmL-LQLPw9XChIljEtS1y8PqSZo8Cs76IUwFskAIgALtC29M0NsLNe0KzkfW_u8VTTMwBaUNMpVJxU1WR-Qj1ZoYXV0aERhdGFZAWc93EcQ6cCIsinbqJ1WMiC7Ofcimv9GWwplaxr7mor4oEEAAAAW8kS2flNkT9WfkMOWInMX2wAglSiFY4VF1uvmq7gZ-85Snh5WAKCRspf0LrkxqSl41vikAQMDOf_-IFkBAL-XpG9vaSdmWz3h1U2yGBNkOGlbkimMoOmAFtZvBhsA9nozhPeYGGsnMf7d9OlT3usy7X_qaaMr-RbHrt5w59dtO-8AJbmo3oErqJSTU1zVw8MZePofpmNtkWNDl0OiD0vsPYiAFSVESbz_JO0OQc_4bJO6cqpeg4kk1QfBYC7ArEql8EQalPaRmfVrTxEh0LINcFV6ou_fCYCmdHjbzq_71agoYkVH_RCDAoB8XktqdMFXgmWvzc8ATHTL6DzGTmUm_snB61TmMQfHAbQ0PcXm8JxVrh-JWgnIdpCJ_WPqYUKGtE3TyzTsnn6qZludLIoGpNHwcq5BIbFo1k48HFEhQwEAAQ',
    clientDataJSON:
      'eyJvcmlnaW4iOiJodHRwczovL2Rldi5kb250bmVlZGEucHciLCJjaGFsbGVuZ2UiOiI2MDAyMTI2OC1jOTJhLTQ4NTUtYjAzZS1iNWNlNTUxMTAwYTQiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0',
  },
  type: 'public-key',
};
const attestationTPMRSASHA1Challenge = '60021268-c92a-4855-b03e-b5ce551100a4';
