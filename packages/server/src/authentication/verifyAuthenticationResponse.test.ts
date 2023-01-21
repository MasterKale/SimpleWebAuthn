import base64url from 'base64url';
import { verifyAuthenticationResponse } from './verifyAuthenticationResponse';

import * as esmDecodeClientDataJSON from '../helpers/decodeClientDataJSON';
import * as esmParseAuthenticatorData from '../helpers/parseAuthenticatorData';
import { toHash } from '../helpers/toHash';
import {
  AuthenticatorDevice,
  AuthenticationCredentialJSON,
} from '@simplewebauthn/typescript-types';
import { DevicePublicKeyAuthenticatorOutput } from '../helpers/decodeAuthenticatorExtensions';

let mockDecodeClientData: jest.SpyInstance;
let mockParseAuthData: jest.SpyInstance;

beforeEach(() => {
  mockDecodeClientData = jest.spyOn(esmDecodeClientDataJSON, 'decodeClientDataJSON');
  mockParseAuthData = jest.spyOn(esmParseAuthenticatorData, 'parseAuthenticatorData');
});

afterEach(() => {
  mockDecodeClientData.mockRestore();
  mockParseAuthData.mockRestore();
});

test('should verify an assertion response', async () => {
  const verification = await verifyAuthenticationResponse({
    credential: assertionResponse,
    expectedChallenge: assertionChallenge,
    expectedOrigin: assertionOrigin,
    expectedRPID: 'dev.dontneeda.pw',
    authenticator: authenticator,
  });

  expect(verification.verified).toEqual(true);
});

test('should return authenticator info after verification', async () => {
  const verification = await verifyAuthenticationResponse({
    credential: assertionResponse,
    expectedChallenge: assertionChallenge,
    expectedOrigin: assertionOrigin,
    expectedRPID: 'dev.dontneeda.pw',
    authenticator: authenticator,
  });

  expect(verification.authenticationInfo.newCounter).toEqual(144);
  expect(verification.authenticationInfo.credentialID).toEqual(authenticator.credentialID);
});

test('should throw when response challenge is not expected value', async () => {
  await expect(
    verifyAuthenticationResponse({
      credential: assertionResponse,
      expectedChallenge: 'shouldhavebeenthisvalue',
      expectedOrigin: 'https://different.address',
      expectedRPID: 'dev.dontneeda.pw',
      authenticator: authenticator,
    }),
  ).rejects.toThrow(/authentication response challenge/i);
});

test('should throw when response origin is not expected value', async () => {
  await expect(
    verifyAuthenticationResponse({
      credential: assertionResponse,
      expectedChallenge: assertionChallenge,
      expectedOrigin: 'https://different.address',
      expectedRPID: 'dev.dontneeda.pw',
      authenticator: authenticator,
    }),
  ).rejects.toThrow(/authentication response origin/i);
});

test('should throw when assertion type is not webauthn.create', async () => {
  // @ts-ignore 2345
  mockDecodeClientData.mockReturnValue({
    origin: assertionOrigin,
    type: 'webauthn.badtype',
    challenge: assertionChallenge,
  });

  await expect(
    verifyAuthenticationResponse({
      credential: assertionResponse,
      expectedChallenge: assertionChallenge,
      expectedOrigin: assertionOrigin,
      expectedRPID: 'dev.dontneeda.pw',
      authenticator: authenticator,
    }),
  ).rejects.toThrow(/authentication response type/i);
});

test('should throw error if user was not present', async () => {
  mockParseAuthData.mockReturnValue({
    rpIdHash: toHash(Buffer.from('dev.dontneeda.pw', 'ascii')),
    flags: 0,
  });

  await expect(
    verifyAuthenticationResponse({
      credential: assertionResponse,
      expectedChallenge: assertionChallenge,
      expectedOrigin: assertionOrigin,
      expectedRPID: 'dev.dontneeda.pw',
      authenticator: authenticator,
    }),
  ).rejects.toThrow(/not present/i);
});

test('should throw error if previous counter value is not less than in response', async () => {
  // This'll match the `counter` value in `assertionResponse`, simulating a potential replay attack
  const badCounter = 144;
  const badDevice = {
    ...authenticator,
    counter: badCounter,
  };

  await expect(
    verifyAuthenticationResponse({
      credential: assertionResponse,
      expectedChallenge: assertionChallenge,
      expectedOrigin: assertionOrigin,
      expectedRPID: 'dev.dontneeda.pw',
      authenticator: badDevice,
    }),
  ).rejects.toThrow(/counter value/i);
});

test('should throw error if assertion RP ID is unexpected value', async () => {
  mockParseAuthData.mockReturnValue({
    rpIdHash: toHash(Buffer.from('bad.url', 'ascii')),
    flags: 0,
  });

  await expect(
    verifyAuthenticationResponse({
      credential: assertionResponse,
      expectedChallenge: assertionChallenge,
      expectedOrigin: assertionOrigin,
      expectedRPID: 'dev.dontneeda.pw',
      authenticator: authenticator,
    }),
  ).rejects.toThrow(/rp id/i);
});

test('should not compare counters if both are 0', async () => {
  const verification = await verifyAuthenticationResponse({
    credential: assertionFirstTimeUsedResponse,
    expectedChallenge: assertionFirstTimeUsedChallenge,
    expectedOrigin: assertionFirstTimeUsedOrigin,
    expectedRPID: 'dev.dontneeda.pw',
    authenticator: authenticatorFirstTimeUsed,
  });

  expect(verification.verified).toEqual(true);
});

test('should throw an error if user verification is required but user was not verified', async () => {
  const actualData = esmParseAuthenticatorData.parseAuthenticatorData(
    base64url.toBuffer(assertionResponse.response.authenticatorData),
  );

  mockParseAuthData.mockReturnValue({
    ...actualData,
    flags: {
      up: true,
      uv: false,
    },
  });

  await expect(
    verifyAuthenticationResponse({
      credential: assertionResponse,
      expectedChallenge: assertionChallenge,
      expectedOrigin: assertionOrigin,
      expectedRPID: 'dev.dontneeda.pw',
      authenticator: authenticator,
      requireUserVerification: true,
    }),
  ).rejects.toThrow(/user could not be verified/i);
});

// TODO: Get a real TPM authentication response in here
test.skip('should verify TPM assertion', async () => {
  const expectedChallenge = 'dG90YWxseVVuaXF1ZVZhbHVlRXZlcnlBc3NlcnRpb24';
  jest.spyOn(base64url, 'encode').mockReturnValueOnce(expectedChallenge);
  const verification = await verifyAuthenticationResponse({
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
      clientExtensionResults: {},
    },
    expectedChallenge,
    expectedOrigin: assertionOrigin,
    expectedRPID: 'dev.dontneeda.pw',
    authenticator: {
      credentialPublicKey: base64url.toBuffer('BAEAAQ'),
      credentialID: base64url.toBuffer('YJ8FMM-AmcUt73XPX341WXWd7ypBMylGjjhu0g3VzME'),
      counter: 0,
    },
  });

  expect(verification.verified).toEqual(true);
});

test('should support multiple possible origins', async () => {
  const verification = await verifyAuthenticationResponse({
    credential: assertionResponse,
    expectedChallenge: assertionChallenge,
    expectedOrigin: ['https://simplewebauthn.dev', assertionOrigin],
    expectedRPID: 'dev.dontneeda.pw',
    authenticator: authenticator,
  });

  expect(verification.verified).toEqual(true);
});

test('should throw an error if origin not in list of expected origins', async () => {
  await expect(
    verifyAuthenticationResponse({
      credential: assertionResponse,
      expectedChallenge: assertionChallenge,
      expectedOrigin: ['https://simplewebauthn.dev', 'https://fizz.buzz'],
      expectedRPID: 'dev.dontneeda.pw',
      authenticator: authenticator,
    }),
  ).rejects.toThrow(/unexpected authentication response origin/i);
});

test('should support multiple possible RP IDs', async () => {
  const verification = await verifyAuthenticationResponse({
    credential: assertionResponse,
    expectedChallenge: assertionChallenge,
    expectedOrigin: assertionOrigin,
    expectedRPID: ['dev.dontneeda.pw', 'simplewebauthn.dev'],
    authenticator: authenticator,
  });

  expect(verification.verified).toEqual(true);
});

test('should throw an error if RP ID not in list of possible RP IDs', async () => {
  await expect(
    verifyAuthenticationResponse({
      credential: assertionResponse,
      expectedChallenge: assertionChallenge,
      expectedOrigin: assertionOrigin,
      expectedRPID: ['simplewebauthn.dev'],
      authenticator: authenticator,
    }),
  ).rejects.toThrow(/unexpected rp id/i);
});

test('should pass verification if custom challenge verifier returns true', async () => {
  const verification = await verifyAuthenticationResponse({
    credential: {
      id: 'AaIBxnYfL2pDWJmIii6CYgHBruhVvFGHheWamphVioG_TnEXxKA9MW4FWnJh21zsbmRpRJso9i2JmAtWOtXfVd4oXTgYVusXwhWWsA',
      rawId:
        'AaIBxnYfL2pDWJmIii6CYgHBruhVvFGHheWamphVioG_TnEXxKA9MW4FWnJh21zsbmRpRJso9i2JmAtWOtXfVd4oXTgYVusXwhWWsA',
      response: {
        authenticatorData: 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFYftypQ',
        clientDataJSON:
          'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiZXlKaFkzUjFZV3hEYUdGc2JHVnVaMlVpT2lKTE0xRjRUMnB1VmtwTWFVZHNibFpGY0RWMllUVlJTbVZOVmxkT1psODNVRmxuZFhSbllrRjBRVlZCSWl3aVlYSmlhWFJ5WVhKNVJHRjBZU0k2SW5OcFoyNU5aVkJzWldGelpTSjkiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjgwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9',
        signature:
          'MEUCIByFAVGfkoKPEzynp-37BX_HOXSaC6-58-ELjB7BG9opAiEAyD_1mN9YAPrphcwpzK3ym2Xx8EjAapgQ326mKgQ1pW0',
        userHandle: 'internalUserId',
      },
      type: 'public-key',
      clientExtensionResults: {},
    },
    expectedChallenge: (challenge: string) => {
      const parsedChallenge: { actualChallenge: string; arbitraryData: string } = JSON.parse(
        base64url.decode(challenge),
      );
      return parsedChallenge.actualChallenge === 'K3QxOjnVJLiGlnVEp5va5QJeMVWNf_7PYgutgbAtAUA';
    },
    expectedOrigin: 'http://localhost:8000',
    expectedRPID: 'localhost',
    authenticator: {
      credentialID: base64url.toBuffer(
        'AaIBxnYfL2pDWJmIii6CYgHBruhVvFGHheWamphVioG_TnEXxKA9MW4FWnJh21zsbmRpRJso9i2JmAtWOtXfVd4oXTgYVusXwhWWsA',
      ),
      credentialPublicKey: base64url.toBuffer(
        'pQECAyYgASFYILTrxTUQv3X4DRM6L_pk65FSMebenhCx3RMsTKoBm-AxIlggEf3qk5552QLNSh1T1oQs7_2C2qysDwN4r4fCp52Hsqs',
      ),
      counter: 0,
    },
  });

  expect(verification.verified).toEqual(true);
});

test('should fail verification if custom challenge verifier returns false', async () => {
  await expect(
    verifyAuthenticationResponse({
      credential: assertionResponse,
      expectedChallenge: challenge => challenge === 'willNeverMatch',
      expectedOrigin: assertionOrigin,
      expectedRPID: 'dev.dontneeda.pw',
      authenticator: authenticator,
    }),
  ).rejects.toThrow(/custom challenge verifier returned false/i);
});

const devicePubKey: DevicePublicKeyAuthenticatorOutput = {
  "dpk": Buffer.from('A5010203262001215820EDEAD3FD35769C23D340DDC1830A7FF20E7355F29D1C75AA0DC2B6AC182EA7D32258203451DC9992AF946825B441945FC9D134E17B73AA5FEA9580351E7C93F5D36513', 'hex'),
  "sig": Buffer.from('3045022100BC6DD9AF5E47BB3AB82731299EAE82A779189E4E416E3A0E37A3BA64C38F991202205671EFAC0E8CD6DE1D3640CE7E4E89D3A97E0517B603D8AC28F23E4E1F74E639', 'hex'),
  "nonce": Buffer.from('', 'hex'),
  "scope": Buffer.from('00', 'hex'),
  "aaguid": Buffer.from('B93FD961F2E6462FB12282002247DE78', 'hex'),
};
const sameDevicePubKey = devicePubKey;
const differentDevicePubKey: DevicePublicKeyAuthenticatorOutput = {
  "dpk": Buffer.from('A5010203262001215820991AABED9DE4271A9EDEAD8806F9DC96D6DCCD0C476253A5510489EC8379BE5B225820A0973CFDEDBB79E27FEF4EE7481673FB3312504DDCA5434CFD23431D6AD29EDA', 'hex'),
  "sig": Buffer.from('3045022049526CD28AEF6B4E621A7D5936D2B504952FC0AE2313A4F0357AAFFFAEA964740221009D513ACAEFB0B32C765AAE6FEBA8C294685EFF63FF1CBF11ECF2107AF4FEB8F8', 'hex'),
  "nonce": Buffer.from('', 'hex'),
  "scope": Buffer.from('00', 'hex'),
  "aaguid": Buffer.from('B93FD961F2E6462FB12282002247DE78', 'hex'),
};
const authenticationCredentialWithDevicePublicKey: AuthenticationCredentialJSON = {
  response: {
    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoicTh1SVR0d0czMkhUU3RmdlVxVTcwWXNGNFJfS1A4WnZEYkVESVpZekNDdyIsIm9yaWdpbiI6ImFuZHJvaWQ6YXBrLWtleS1oYXNoOmd4N3NxX3B4aHhocklRZEx5ZkcwcHhLd2lKN2hPazJESlE0eHZLZDQzOFEiLCJhbmRyb2lkUGFja2FnZU5hbWUiOiJjb20uZmlkby5leGFtcGxlLmZpZG8yYXBpZXhhbXBsZSJ9",
    "authenticatorData": "DXX8xWP9p3nbLjQ-6kiYiHWLeFSdSTpP2-oc2WqjHMSFAAAAAKFsZGV2aWNlUHViS2V5pWNkcGtYTaUBAgMmIAEhWCDt6tP9NXacI9NA3cGDCn_yDnNV8p0cdaoNwrasGC6n0yJYIDRR3JmSr5RoJbRBlF_J0TThe3OqX-qVgDUefJP102UTY3NpZ1hHMEUCIQC8bdmvXke7OrgnMSmeroKneRieTkFuOg43o7pkw4-ZEgIgVnHvrA6M1t4dNkDOfk6J06l-BRe2A9isKPI-Th905jllbm9uY2VAZXNjb3BlQQBmYWFndWlkULk_2WHy5kYvsSKCACJH3ng=",
    "signature": "MEUCIEXJbR9-0cpcUdGAJi25Qf3z22lnCidx3box2b0bWKhwAiEAkp5zCbVbN2CEtIyezQEa9SOG62xm8YHdE1G5qov64j8=",
    "userHandle": "b2FPajFxcmM4MWo3QkFFel9RN2lEakh5RVNlU2RLNDF0Sl92eHpQYWV5UQ=="
  },
  id: "cxjDB1h5nG6jpQW3EeeZNA",
  rawId: "cxjDB1h5nG6jpQW3EeeZNA",
  type: "public-key",
  clientExtensionResults: {}
};
const credentialID = base64url.toBuffer('cxjDB1h5nG6jpQW3EeeZNA');
const credentialPublicKey = base64url.toBuffer('pQECAyYgASFYIIukb9t-EtGUOa2t6YiJEAgz7GyqBN4DFTCzkcMiUGqIIlggmm6GzBPSzP9IYJnX-89R_zmKl6-qQSeQ2qomEC6Cr30');

test('should throw if multiple device public key matches', async () => {
  await expect(verifyAuthenticationResponse({
    credential: authenticationCredentialWithDevicePublicKey,
    expectedOrigin: 'android:apk-key-hash:gx7sq_pxhxhrIQdLyfG0pxKwiJ7hOk2DJQ4xvKd438Q',
    expectedRPID: 'try-webauthn.appspot.com',
    expectedChallenge: 'q8uITtwG32HTStfvUqU70YsF4R_KP8ZvDbEDIZYzCCw',
    authenticator: {
      credentialID,
      credentialPublicKey,
      counter: 0,
    },
    userDevicePublicKeys: [sameDevicePubKey, sameDevicePubKey],
  })).rejects.toThrowError(new Error('It is undetermined whether this is a known device.'));
});

test('should return the new device public key when no device public key matches', async () => {
  await expect(verifyAuthenticationResponse({
    credential: authenticationCredentialWithDevicePublicKey,
    expectedOrigin: 'android:apk-key-hash:gx7sq_pxhxhrIQdLyfG0pxKwiJ7hOk2DJQ4xvKd438Q',
    expectedRPID: 'try-webauthn.appspot.com',
    expectedChallenge: 'q8uITtwG32HTStfvUqU70YsF4R_KP8ZvDbEDIZYzCCw',
    authenticator: {
      credentialID,
      credentialPublicKey,
      counter: 0,
    },
    userDevicePublicKeys: [differentDevicePubKey, differentDevicePubKey],
  }).then(verification => verification.authenticationInfo.extensionOutputs?.devicePubKeyToStore)).resolves.toMatchObject(devicePubKey);
});

test('should return undefined when one device public key matches', async () => {
  await expect(verifyAuthenticationResponse({
    credential: authenticationCredentialWithDevicePublicKey,
    expectedOrigin: 'android:apk-key-hash:gx7sq_pxhxhrIQdLyfG0pxKwiJ7hOk2DJQ4xvKd438Q',
    expectedRPID: 'try-webauthn.appspot.com',
    expectedChallenge: 'q8uITtwG32HTStfvUqU70YsF4R_KP8ZvDbEDIZYzCCw',
    authenticator: {
      credentialID,
      credentialPublicKey,
      counter: 0,
    },
    userDevicePublicKeys: [sameDevicePubKey, differentDevicePubKey]
  }).then(verification => verification.authenticationInfo.extensionOutputs?.devicePubKeyToStore)).resolves.toBeUndefined();
});

test('should return credential backup info', async () => {
  const verification = await verifyAuthenticationResponse({
    credential: assertionResponse,
    expectedChallenge: assertionChallenge,
    expectedOrigin: assertionOrigin,
    expectedRPID: 'dev.dontneeda.pw',
    authenticator: authenticator,
  });

  expect(verification.authenticationInfo?.credentialDeviceType).toEqual('singleDevice');
  expect(verification.authenticationInfo?.credentialBackedUp).toEqual(false);
});

/**
 * Assertion examples below
 */

const assertionResponse: AuthenticationCredentialJSON = {
  id: 'KEbWNCc7NgaYnUyrNeFGX9_3Y-8oJ3KwzjnaiD1d1LVTxR7v3CaKfCz2Vy_g_MHSh7yJ8yL0Pxg6jo_o0hYiew',
  rawId: 'KEbWNCc7NgaYnUyrNeFGX9_3Y-8oJ3KwzjnaiD1d1LVTxR7v3CaKfCz2Vy_g_MHSh7yJ8yL0Pxg6jo_o0hYiew',
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
  clientExtensionResults: {},
  type: 'public-key',
};
const assertionChallenge = base64url.encode('totallyUniqueValueEveryTime');
const assertionOrigin = 'https://dev.dontneeda.pw';

const authenticator: AuthenticatorDevice = {
  credentialPublicKey: base64url.toBuffer(
    'pQECAyYgASFYIIheFp-u6GvFT2LNGovf3ZrT0iFVBsA_76rRysxRG9A1Ilgg8WGeA6hPmnab0HAViUYVRkwTNcN77QBf_RR0dv3lIvQ',
  ),
  credentialID: base64url.toBuffer(
    'KEbWNCc7NgaYnUyrNeFGX9_3Y-8oJ3KwzjnaiD1d1LVTxR7v3CaKfCz2Vy_g_MHSh7yJ8yL0Pxg6jo_o0hYiew',
  ),
  counter: 143,
};

/**
 * Represented a device that's being used on the website for the first time
 */
const assertionFirstTimeUsedResponse: AuthenticationCredentialJSON = {
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
  clientExtensionResults: {},
};
const assertionFirstTimeUsedChallenge = base64url.encode('totallyUniqueValueEveryAssertion');
const assertionFirstTimeUsedOrigin = 'https://dev.dontneeda.pw';
const authenticatorFirstTimeUsed: AuthenticatorDevice = {
  credentialPublicKey: base64url.toBuffer(
    'pQECAyYgASFYIGmaxR4mBbukc2QhtW2ldhAAd555r-ljlGQN8MbcTnPPIlgg9CyUlE-0AB2fbzZbNgBvJuRa7r6o2jPphOmtyNPR_kY',
  ),
  credentialID: base64url.toBuffer(
    'wSisR0_4hlzw3Y1tj4uNwwifIhRa-ZxWJwWbnfror0pVK9qPdBPO5pW3gasPqn6wXHb0LNhXB_IrA1nFoSQJ9A',
  ),
  counter: 0,
};

test('should return user verified flag after successful auth', async () => {
  const verification = await verifyAuthenticationResponse({
    credential: assertionResponse,
    expectedChallenge: assertionChallenge,
    expectedOrigin: assertionOrigin,
    expectedRPID: 'dev.dontneeda.pw',
    authenticator: authenticator,
  });

  expect(verification.authenticationInfo?.userVerified).toBeDefined();
  expect(verification.authenticationInfo?.userVerified).toEqual(false);
});
