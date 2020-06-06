import verifyAttestationResponse from './verifyAttestationResponse';

import * as decodeAttestationObject from '../helpers/decodeAttestationObject';
import * as decodeClientDataJSON from '../helpers/decodeClientDataJSON';

let mockDecodeAttestation: jest.SpyInstance;
let mockDecodeClientData: jest.SpyInstance;

beforeEach(() => {
  mockDecodeAttestation = jest.spyOn(decodeAttestationObject, 'default');
  mockDecodeClientData = jest.spyOn(decodeClientDataJSON, 'default');
});

afterEach(() => {
  mockDecodeAttestation.mockRestore();
  mockDecodeClientData.mockRestore();
});

test('should verify FIDO U2F attestation', () => {
  const verification = verifyAttestationResponse(
    attestationFIDOU2F,
    attestationFIDOU2FChallenge,
    'https://dev.dontneeda.pw',
    'dev.dontneeda.pw',
  );

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
  const verification = verifyAttestationResponse(
    attestationPacked,
    attestationPackedChallenge,
    'https://dev.dontneeda.pw',
    'dev.dontneeda.pw',
  );

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
  const verification = verifyAttestationResponse(
    attestationPackedX5C,
    attestationPackedX5CChallenge,
    'https://dev.dontneeda.pw',
    'dev.dontneeda.pw',
  );

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
  const verification = verifyAttestationResponse(
    attestationNone,
    attestationNoneChallenge,
    'https://dev.dontneeda.pw',
    'dev.dontneeda.pw',
  );

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

test('should verify Android SafetyNet attestation', () => {
  const verification = verifyAttestationResponse(
    attestationAndroidSafetyNet,
    attestationAndroidSafetyNetChallenge,
    'https://dev.dontneeda.pw',
    'dev.dontneeda.pw',
  );

  expect(verification.verified).toEqual(true);
  expect(verification.authenticatorInfo?.fmt).toEqual('android-safetynet');
  expect(verification.authenticatorInfo?.counter).toEqual(0);
  expect(verification.authenticatorInfo?.base64PublicKey).toEqual(
    'BJPiEh3cHIn9qBHLOe_XEhrPHaeVUQbK83uKe2hmvsLYqjdcH5xxr1pQ4sL7GGncZ-HJ9NLSGPCznMv9tP83UAs',
  );
  expect(verification.authenticatorInfo?.base64CredentialID).toEqual(
    'AQy9gSmVYQXGuzd492rA2qEqwN7SYE_xOCjduU4QVagRwnX30mbfW75Lu4TwXHe-gc1O2PnJF7JVJA9dyJm83Xs',
  );
});

test('should throw when response challenge is not expected value', () => {
  expect(() => {
    verifyAttestationResponse(
      attestationNone,
      'shouldhavebeenthisvalue',
      'https://dev.dontneeda.pw',
      'dev.dontneeda.pw',
    );
  }).toThrow(/attestation challenge/i);
});

test('should throw when response origin is not expected value', () => {
  expect(() => {
    verifyAttestationResponse(
      attestationNone,
      attestationNoneChallenge,
      'https://different.address',
      'dev.dontneeda.pw',
    );
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
    verifyAttestationResponse(attestationNone, challenge, origin, 'dev.dontneeda.pw');
  }).toThrow(/attestation type/i);
});

test('should throw if an unexpected attestation format is specified', () => {
  const fmt = 'fizzbuzz';

  mockDecodeAttestation.mockReturnValue({
    // @ts-ignore 2322
    fmt,
  });

  expect(() => {
    verifyAttestationResponse(
      attestationNone,
      attestationNoneChallenge,
      'https://dev.dontneeda.pw',
      '',
    );
  }).toThrow();
});

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
  id: '',
  rawId: '',
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
  type: 'webauthn.create',
};
const attestationPackedChallenge = 's6PIbBnPPnrGNSBxNdtDrT7UrVYJK9HM';

const attestationPackedX5C = {
  // TODO: Grab these from another iPhone attestation
  id: '',
  rawId: '',
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
  type: 'webauthn.create',
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
  type: 'webauthn.create',
};
const attestationNoneChallenge = 'hEccPWuziP00H0p5gxh2_u5_PC4NeYgd';

const attestationAndroidSafetyNet = {
  id: 'AQy9gSmVYQXGuzd492rA2qEqwN7SYE_xOCjduU4QVagRwnX30mbfW75Lu4TwXHe-gc1O2PnJF7JVJA9dyJm83Xs',
  rawId: 'AQy9gSmVYQXGuzd492rA2qEqwN7SYE_xOCjduU4QVagRwnX30mbfW75Lu4TwXHe-gc1O2PnJF7JVJA9dyJm83Xs',
  response: {
    attestationObject:
      'o2NmbXRxYW5kcm9pZC1zYWZldHluZXRnYXR0U3RtdKJjdmVyaDE3MTIyMDM3aHJlc' +
      '3BvbnNlWRS9ZXlKaGJHY2lPaUpTVXpJMU5pSXNJbmcxWXlJNld5Sk5TVWxHYTJwRFEwSkljV2RCZDBsQ1FXZEpVV' +
      'kpZY205T01GcFBaRkpyUWtGQlFVRkJRVkIxYm5wQlRrSm5hM0ZvYTJsSE9YY3dRa0ZSYzBaQlJFSkRUVkZ6ZDBOU' +
      'ldVUldVVkZIUlhkS1ZsVjZSV1ZOUW5kSFFURlZSVU5vVFZaU01qbDJXako0YkVsR1VubGtXRTR3U1VaT2JHTnVXb' +
      'kJaTWxaNlRWSk5kMFZSV1VSV1VWRkVSWGR3U0ZaR1RXZFJNRVZuVFZVNGVFMUNORmhFVkVVMFRWUkJlRTFFUVROT' +
      'lZHc3dUbFp2V0VSVVJUVk5WRUYzVDFSQk0wMVVhekJPVm05M1lrUkZURTFCYTBkQk1WVkZRbWhOUTFaV1RYaEZla' +
      '0ZTUW1kT1ZrSkJaMVJEYTA1b1lrZHNiV0l6U25WaFYwVjRSbXBCVlVKblRsWkNRV05VUkZVeGRtUlhOVEJaVjJ4M' +
      'VNVWmFjRnBZWTNoRmVrRlNRbWRPVmtKQmIxUkRhMlIyWWpKa2MxcFRRazFVUlUxNFIzcEJXa0puVGxaQ1FVMVVSV' +
      'zFHTUdSSFZucGtRelZvWW0xU2VXSXliR3RNYlU1MllsUkRRMEZUU1hkRVVWbEtTMjlhU1doMlkwNUJVVVZDUWxGQ' +
      'lJHZG5SVkJCUkVORFFWRnZRMmRuUlVKQlRtcFlhM293WlVzeFUwVTBiU3N2UnpWM1QyOHJXRWRUUlVOeWNXUnVPR' +
      'Gh6UTNCU04yWnpNVFJtU3pCU2FETmFRMWxhVEVaSWNVSnJOa0Z0V2xaM01rczVSa2N3VHpseVVsQmxVVVJKVmxKN' +
      'VJUTXdVWFZ1VXpsMVowaEROR1ZuT1c5MmRrOXRLMUZrV2pKd09UTllhSHAxYmxGRmFGVlhXRU40UVVSSlJVZEtTe' +
      'k5UTW1GQlpucGxPVGxRVEZNeU9XaE1ZMUYxV1ZoSVJHRkROMDlhY1U1dWIzTnBUMGRwWm5NNGRqRnFhVFpJTDNob' +
      '2JIUkRXbVV5YkVvck4wZDFkSHBsZUV0d2VIWndSUzkwV2xObVlsazVNRFZ4VTJ4Q2FEbG1jR293TVRWamFtNVJSb' +
      'XRWYzBGVmQyMUxWa0ZWZFdWVmVqUjBTMk5HU3pSd1pYWk9UR0Y0UlVGc0swOXJhV3hOZEVsWlJHRmpSRFZ1Wld3M' +
      'GVFcHBlWE0wTVROb1lXZHhWekJYYUdnMVJsQXpPV2hIYXpsRkwwSjNVVlJxWVhwVGVFZGtkbGd3YlRaNFJsbG9hQ' +
      'zh5VmsxNVdtcFVORXQ2VUVwRlEwRjNSVUZCWVU5RFFXeG5kMmRuU2xWTlFUUkhRVEZWWkVSM1JVSXZkMUZGUVhkS' +
      'lJtOUVRVlJDWjA1V1NGTlZSVVJFUVV0Q1oyZHlRbWRGUmtKUlkwUkJWRUZOUW1kT1ZraFNUVUpCWmpoRlFXcEJRV' +
      'TFDTUVkQk1WVmtSR2RSVjBKQ1VYRkNVWGRIVjI5S1FtRXhiMVJMY1hWd2J6UlhObmhVTm1veVJFRm1RbWRPVmtoV' +
      'FRVVkhSRUZYWjBKVFdUQm1hSFZGVDNaUWJTdDRaMjU0YVZGSE5rUnlabEZ1T1V0NlFtdENaMmR5UW1kRlJrSlJZM' +
      'EpCVVZKWlRVWlpkMHAzV1VsTGQxbENRbEZWU0UxQlIwZEhNbWd3WkVoQk5reDVPWFpaTTA1M1RHNUNjbUZUTlc1a' +
      'U1qbHVUREprTUdONlJuWk5WRUZ5UW1kbmNrSm5SVVpDVVdOM1FXOVpabUZJVWpCalJHOTJURE5DY21GVE5XNWlNa' +
      'mx1VERKa2VtTnFTWFpTTVZKVVRWVTRlRXh0VG5sa1JFRmtRbWRPVmtoU1JVVkdha0ZWWjJoS2FHUklVbXhqTTFGM' +
      'VdWYzFhMk50T1hCYVF6VnFZakl3ZDBsUldVUldVakJuUWtKdmQwZEVRVWxDWjFwdVoxRjNRa0ZuU1hkRVFWbExTM' +
      '2RaUWtKQlNGZGxVVWxHUVhwQmRrSm5UbFpJVWpoRlMwUkJiVTFEVTJkSmNVRm5hR2cxYjJSSVVuZFBhVGgyV1ROS' +
      '2MweHVRbkpoVXpWdVlqSTVia3d3WkZWVmVrWlFUVk0xYW1OdGQzZG5aMFZGUW1kdmNrSm5SVVZCWkZvMVFXZFJRM' +
      'EpKU0RGQ1NVaDVRVkJCUVdSM1EydDFVVzFSZEVKb1dVWkpaVGRGTmt4TldqTkJTMUJFVjFsQ1VHdGlNemRxYW1RN' +
      'E1FOTVRVE5qUlVGQlFVRlhXbVJFTTFCTVFVRkJSVUYzUWtsTlJWbERTVkZEVTFwRFYyVk1Tblp6YVZaWE5rTm5LM' +
      'mRxTHpsM1dWUktVbnAxTkVocGNXVTBaVmswWXk5dGVYcHFaMGxvUVV4VFlta3ZWR2g2WTNweGRHbHFNMlJyTTNaa' +
      'VRHTkpWek5NYkRKQ01HODNOVWRSWkdoTmFXZGlRbWRCU0ZWQlZtaFJSMjFwTDFoM2RYcFVPV1ZIT1ZKTVNTdDRNR' +
      'm95ZFdKNVdrVldla0UzTlZOWlZtUmhTakJPTUVGQlFVWnRXRkU1ZWpWQlFVRkNRVTFCVW1wQ1JVRnBRbU5EZDBFN' +
      'WFqZE9WRWRZVURJM09IbzBhSEl2ZFVOSWFVRkdUSGx2UTNFeVN6QXJlVXhTZDBwVlltZEpaMlk0WjBocWRuQjNNb' +
      'TFDTVVWVGFuRXlUMll6UVRCQlJVRjNRMnR1UTJGRlMwWlZlVm8zWmk5UmRFbDNSRkZaU2t0dldrbG9kbU5PUVZGR' +
      'lRFSlJRVVJuWjBWQ1FVazVibFJtVWt0SlYyZDBiRmRzTTNkQ1REVTFSVlJXTm10aGVuTndhRmN4ZVVGak5VUjFiV' +
      'FpZVHpReGExcDZkMG8yTVhkS2JXUlNVbFF2VlhORFNYa3hTMFYwTW1Nd1JXcG5iRzVLUTBZeVpXRjNZMFZYYkV4U' +
      'ldUSllVRXg1Um1wclYxRk9ZbE5vUWpGcE5GY3lUbEpIZWxCb2RETnRNV0kwT1doaWMzUjFXRTAyZEZnMVEzbEZTR' +
      'zVVYURoQ2IyMDBMMWRzUm1sb2VtaG5iamd4Ukd4a2IyZDZMMHN5VlhkTk5sTTJRMEl2VTBWNGEybFdabllyZW1KS' +
      '01ISnFkbWM1TkVGc1pHcFZabFYzYTBrNVZrNU5ha1ZRTldVNGVXUkNNMjlNYkRabmJIQkRaVVkxWkdkbVUxZzBWV' +
      'Gw0TXpWdmFpOUpTV1F6VlVVdlpGQndZaTl4WjBkMmMydG1aR1Y2ZEcxVmRHVXZTMU50Y21sM1kyZFZWMWRsV0daV' +
      'Vlra3plbk5wYTNkYVltdHdiVkpaUzIxcVVHMW9kalJ5YkdsNlIwTkhkRGhRYmpod2NUaE5Na3RFWmk5UU0ydFdiM' +
      '1F6WlRFNFVUMGlMQ0pOU1VsRlUycERRMEY2UzJkQmQwbENRV2RKVGtGbFR6QnRjVWRPYVhGdFFrcFhiRkYxUkVGT' +
      '1FtZHJjV2hyYVVjNWR6QkNRVkZ6UmtGRVFrMU5VMEYzU0dkWlJGWlJVVXhGZUdSSVlrYzVhVmxYZUZSaFYyUjFTV' +
      'VpLZG1JelVXZFJNRVZuVEZOQ1UwMXFSVlJOUWtWSFFURlZSVU5vVFV0U01uaDJXVzFHYzFVeWJHNWlha1ZVVFVKR' +
      'lIwRXhWVVZCZUUxTFVqSjRkbGx0Um5OVk1teHVZbXBCWlVaM01IaE9la0V5VFZSVmQwMUVRWGRPUkVwaFJuY3dlV' +
      'TFVUlhsTlZGVjNUVVJCZDA1RVNtRk5SVWw0UTNwQlNrSm5UbFpDUVZsVVFXeFdWRTFTTkhkSVFWbEVWbEZSUzBWN' +
      'FZraGlNamx1WWtkVloxWklTakZqTTFGblZUSldlV1J0YkdwYVdFMTRSWHBCVWtKblRsWkNRVTFVUTJ0a1ZWVjVRa' +
      '1JSVTBGNFZIcEZkMmRuUldsTlFUQkhRMU54UjFOSllqTkVVVVZDUVZGVlFVRTBTVUpFZDBGM1oyZEZTMEZ2U1VKQ' +
      'lVVUlJSMDA1UmpGSmRrNHdOWHByVVU4NUszUk9NWEJKVW5aS2VucDVUMVJJVnpWRWVrVmFhRVF5WlZCRGJuWlZRV' +
      'EJSYXpJNFJtZEpRMlpMY1VNNVJXdHpRelJVTW1aWFFsbHJMMnBEWmtNelVqTldXazFrVXk5a1RqUmFTME5GVUZwU' +
      '2NrRjZSSE5wUzFWRWVsSnliVUpDU2pWM2RXUm5lbTVrU1UxWlkweGxMMUpIUjBac05YbFBSRWxMWjJwRmRpOVRTa' +
      '2d2VlV3clpFVmhiSFJPTVRGQ2JYTkxLMlZSYlUxR0t5dEJZM2hIVG1oeU5UbHhUUzg1YVd3M01Va3laRTQ0Umtkb' +
      'VkyUmtkM1ZoWldvMFlsaG9jREJNWTFGQ1ltcDRUV05KTjBwUU1HRk5NMVEwU1N0RWMyRjRiVXRHYzJKcWVtRlVUa' +
      '001ZFhwd1JteG5UMGxuTjNKU01qVjRiM2x1VlhoMk9IWk9iV3R4TjNwa1VFZElXR3Q0VjFrM2IwYzVhaXRLYTFKN' +
      'VFrRkNhemRZY2twbWIzVmpRbHBGY1VaS1NsTlFhemRZUVRCTVMxY3dXVE42Tlc5Nk1rUXdZekYwU2t0M1NFRm5UV' +
      'UpCUVVkcVoyZEZlazFKU1VKTWVrRlBRbWRPVmtoUk9FSkJaamhGUWtGTlEwRlpXWGRJVVZsRVZsSXdiRUpDV1hkR' +
      '1FWbEpTM2RaUWtKUlZVaEJkMFZIUTBOelIwRlJWVVpDZDAxRFRVSkpSMEV4VldSRmQwVkNMM2RSU1UxQldVSkJaa' +
      'mhEUVZGQmQwaFJXVVJXVWpCUFFrSlpSVVpLYWxJclJ6UlJOamdyWWpkSFEyWkhTa0ZpYjA5ME9VTm1NSEpOUWpoS' +
      'FFURlZaRWwzVVZsTlFtRkJSa3AyYVVJeFpHNUlRamRCWVdkaVpWZGlVMkZNWkM5alIxbFpkVTFFVlVkRFEzTkhRV' +
      'kZWUmtKM1JVSkNRMnQzU25wQmJFSm5aM0pDWjBWR1FsRmpkMEZaV1ZwaFNGSXdZMFJ2ZGt3eU9XcGpNMEYxWTBkM' +
      'GNFeHRaSFppTW1OMldqTk9lVTFxUVhsQ1owNVdTRkk0UlV0NlFYQk5RMlZuU21GQmFtaHBSbTlrU0ZKM1QyazRkb' +
      'Gt6U25OTWJrSnlZVk0xYm1JeU9XNU1NbVI2WTJwSmRsb3pUbmxOYVRWcVkyMTNkMUIzV1VSV1VqQm5Ra1JuZDA1c' +
      'VFUQkNaMXB1WjFGM1FrRm5TWGRMYWtGdlFtZG5ja0puUlVaQ1VXTkRRVkpaWTJGSVVqQmpTRTAyVEhrNWQyRXlhM' +
      '1ZhTWpsMlduazVlVnBZUW5aak1td3dZak5LTlV4NlFVNUNaMnR4YUd0cFJ6bDNNRUpCVVhOR1FVRlBRMEZSUlVGS' +
      'GIwRXJUbTV1TnpoNU5uQlNhbVE1V0d4UlYwNWhOMGhVWjJsYUwzSXpVazVIYTIxVmJWbElVRkZ4TmxOamRHazVVR' +
      'VZoYW5aM1VsUXlhVmRVU0ZGeU1ESm1aWE54VDNGQ1dUSkZWRlYzWjFwUksyeHNkRzlPUm5ab2MwODVkSFpDUTA5S' +
      'llYcHdjM2RYUXpsaFNqbDRhblUwZEZkRVVVZzRUbFpWTmxsYVdpOVlkR1ZFVTBkVk9WbDZTbkZRYWxrNGNUTk5SS' +
      'Gh5ZW0xeFpYQkNRMlkxYnpodGR5OTNTalJoTWtjMmVIcFZjalpHWWpaVU9FMWpSRTh5TWxCTVVrdzJkVE5OTkZSN' +
      'mN6TkJNazB4YWpaaWVXdEtXV2s0ZDFkSlVtUkJka3RNVjFwMUwyRjRRbFppZWxsdGNXMTNhMjAxZWt4VFJGYzFia' +
      '2xCU21KRlRFTlJRMXAzVFVnMU5uUXlSSFp4YjJaNGN6WkNRbU5EUmtsYVZWTndlSFUyZURaMFpEQldOMU4yU2tOR' +
      'GIzTnBjbE50U1dGMGFpODVaRk5UVmtSUmFXSmxkRGh4THpkVlN6UjJORnBWVGpnd1lYUnVXbm94ZVdjOVBTSmRmU' +
      'S5leUp1YjI1alpTSTZJbkZyYjB4dE9XSnJUeXNyYzJoMFZITnZheXRqUW1GRmJFcEJXa1pXTUcxRlFqQTVVbWcxV' +
      'TNKWVpGVTlJaXdpZEdsdFpYTjBZVzF3VFhNaU9qRTFOalUwTWpReU5qSTNOek1zSW1Gd2ExQmhZMnRoWjJWT1lXM' +
      'WxJam9pWTI5dExtZHZiMmRzWlM1aGJtUnliMmxrTG1kdGN5SXNJbUZ3YTBScFoyVnpkRk5vWVRJMU5pSTZJaXR0Y' +
      '0ZKQ016RjRRemRTYUdsaWN5OWxWbUVyTDNWQ05XNTFaMVVyV0UxRFFXa3plSFZKZGpaMGIwMDlJaXdpWTNSelVIS' +
      'nZabWxzWlUxaGRHTm9JanAwY25WbExDSmhjR3REWlhKMGFXWnBZMkYwWlVScFoyVnpkRk5vWVRJMU5pSTZXeUk0V' +
      'URGelZ6QkZVRXBqYzJ4M04xVjZVbk5wV0V3Mk5IY3JUelV3UldRclVrSkpRM1JoZVRGbk1qUk5QU0pkTENKaVlYT' +
      'nBZMGx1ZEdWbmNtbDBlU0k2ZEhKMVpYMC5yUW5Ib2FZVGgxTEU2VVZwaU1lZWFidDdUeWJ3dzdXZk42RzJ5R01tZ' +
      'kVjbTFabjRWalZkenpoY1BqTS1WR052aWl1RGxyZ2VuWEViZ082V05YNlYzc0hHVjN1VGxGMlBuOUZsY3YxWmItS' +
      '2NGVHZUd29iYnY3LUp5VUZzTlhTSnhHZFRTOWxwNU5EdDFnWGJ6OVpORWhzVXI3ajBqbWNyaU9rR29PRzM4MXRSa' +
      '0Vqdk5aa0hpMkF1UDF2MWM4RXg3cEpZc09ISzJxaDlmSHFuSlAzcGowUFc3WThpcDBSTVZaNF9xZzFqc0dMMnZ0O' +
      'G12cEJFMjg5dE1fcnROdm94TWU2aEx0Q1ZkdE9ZRjIzMWMtWVFJd2FEbnZWdDcwYW5XLUZYdUx3R1J5dWhfRlpNM' +
      '3FCSlhhcXdCNjNITk5uMmh5MFRDdHQ4RDdIMmI4MGltWkZRX1FoYXV0aERhdGFYxT3cRxDpwIiyKduonVYyILs59' +
      'yKa_0ZbCmVrGvuaivigRQAAAAC5P9lh8uZGL7EiggAiR954AEEBDL2BKZVhBca7N3j3asDaoSrA3tJgT_E4KN25T' +
      'hBVqBHCdffSZt9bvku7hPBcd76BzU7Y-ckXslUkD13Imbzde6UBAgMmIAEhWCCT4hId3ByJ_agRyznv1xIazx2nl' +
      'VEGyvN7intoZr7C2CJYIKo3XB-cca9aUOLC-xhp3GfhyfTS0hjws5zL_bT_N1AL',
    clientDataJSON:
      'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiWDNaV1VHOUZOREpF' +
      'YUMxM2F6Tmlka2h0WVd0MGFWWjJSVmxETFV4M1FsZyIsIm9yaWdpbiI6Imh0dHBzOlwvXC9kZXYuZG9udG5lZWRh' +
      'LnB3IiwiYW5kcm9pZFBhY2thZ2VOYW1lIjoiY29tLmFuZHJvaWQuY2hyb21lIn0',
  },
  getClientExtensionResults: () => ({}),
  type: 'webauthn.create',
};
const attestationAndroidSafetyNetChallenge = '_vVPoE42Dh-wk3bvHmaktiVvEYC-LwBX';
