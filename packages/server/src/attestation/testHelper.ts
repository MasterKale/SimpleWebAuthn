import { PublicKeyCredentialCreationOptionsJSON } from '@simplewebauthn/typescript-types';
import base64url from 'base64url';

export const attestationCredential = {
  id: 'VHzbxaYaJu2P8m1Y2iHn2gRNHrgK0iYbn9E978L3Qi7Q-chFeicIHwYCRophz5lth2nCgEVKcgWirxlgidgbUQ',
  rawId: 'VHzbxaYaJu2P8m1Y2iHn2gRNHrgK0iYbn9E978L3Qi7Q-chFeicIHwYCRophz5lth2nCgEVKcgWirxlgidgbUQ',
  adapters: {},
  response: {
    attestationObject:
      'o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgRYUftNUmhT0VWTZmIgDmrOoP26Pcre-kL3DLnCrXbegCIQCOu_x5gqp-Rej76zeBuXlk8e7J-9WM_i-wZmCIbIgCGmN4NWOBWQLBMIICvTCCAaWgAwIBAgIEKudiYzANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgNzE5ODA3MDc1MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKgOGXmBD2Z4R_xCqJVRXhL8Jr45rHjsyFykhb1USGozZENOZ3cdovf5Ke8fj2rxi5tJGn_VnW4_6iQzKdIaeP6NsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjEwEwYLKwYBBAGC5RwCAQEEBAMCBDAwIQYLKwYBBAGC5RwBAQQEEgQQbUS6m_bsLkm5MAyP6SDLczAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQByV9A83MPhFWmEkNb4DvlbUwcjc9nmRzJjKxHc3HeK7GvVkm0H4XucVDB4jeMvTke0WHb_jFUiApvpOHh5VyMx5ydwFoKKcRs5x0_WwSWL0eTZ5WbVcHkDR9pSNcA_D_5AsUKOBcbpF5nkdVRxaQHuuIuwV4k1iK2IqtMNcU8vL6w21U261xCcWwJ6sMq4zzVO8QCKCQhsoIaWrwz828GDmPzfAjFsJiLJXuYivdHACkeJ5KHMt0mjVLpfJ2BCML7_rgbmvwL7wBW80VHfNdcKmKjkLcpEiPzwcQQhiN_qHV90t-p4iyr5xRSpurlP5zic2hlRkLKxMH2_kRjhqSn4aGF1dGhEYXRhWMQ93EcQ6cCIsinbqJ1WMiC7Ofcimv9GWwplaxr7mor4oEEAAAAAAAAAAAAAAAAAAAAAAAAAAABAVHzbxaYaJu2P8m1Y2iHn2gRNHrgK0iYbn9E978L3Qi7Q-chFeicIHwYCRophz5lth2nCgEVKcgWirxlgidgbUaUBAgMmIAEhWCDIkcsOaVKDIQYwq3EDQ-pST2kRwNH_l1nCgW-WcFpNXiJYIBSbummp-KO3qZeqmvZ_U_uirCDL2RNj3E5y4_KzefIr',
    clientDataJSON:
      'eyJjaGFsbGVuZ2UiOiJkRzkwWVd4c2VWVnVhWEYxWlZaaGJIVmxSWFpsY25sQmRIUmxjM1JoZEdsdmJnIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9kZXYuZG9udG5lZWRhLnB3IiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9',
  },
  // eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
  getClientExtensionResults: () => ({}),
  type: 'public-key',
};
export const attestationChallenge = base64url.encode('totallyUniqueValueEveryAttestation');
export const attestationOrigin = 'https://dev.dontneeda.pw';
export const attestationRPID = 'dev.dontneeda.pw';

// eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
export const getVerifyAttestOptions = () => ({
  credential: attestationCredential,
  expectedChallenge: attestationChallenge,
  expectedOrigin: attestationOrigin,
  expectedRPID: attestationRPID,
});

export const getAttestResponse = () =>
  ({
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
  } as PublicKeyCredentialCreationOptionsJSON);