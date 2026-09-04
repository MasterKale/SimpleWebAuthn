import {
  assert,
  assertEquals,
  assertExists,
  assertFalse,
  assertObjectMatch,
  assertRejects,
} from '@std/assert';
import { returnsNext, stub } from '@std/testing/mock';

import { verifyAuthenticationResponse } from './verifyAuthenticationResponse.ts';

import type { AuthenticationResponseJSON, WebAuthnCredential } from '../types/index.ts';
import { _decodeClientDataJSONInternals } from '../helpers/decodeClientDataJSON.ts';
import {
  _parseAuthenticatorDataInternals,
  parseAuthenticatorData,
} from '../helpers/parseAuthenticatorData.ts';
import { toHash } from '../helpers/toHash.ts';
import { isoBase64URL, isoUint8Array } from '../helpers/iso/index.ts';
import { denoSupportsPQC } from '../helpers/tests/index.ts';
import { PQCNotSupportedError } from '../errors/index.ts';

Deno.test('should verify an assertion response', async () => {
  const verification = await verifyAuthenticationResponse({
    response: assertionResponse,
    expectedChallenge: assertionChallenge,
    expectedOrigin: assertionOrigin,
    expectedRPID: 'dev.dontneeda.pw',
    credential,
    requireUserVerification: false,
  });

  assertEquals(verification.verified, true);
});

Deno.test('should return authenticator info after verification', async () => {
  const verification = await verifyAuthenticationResponse({
    response: assertionResponse,
    expectedChallenge: assertionChallenge,
    expectedOrigin: assertionOrigin,
    expectedRPID: 'dev.dontneeda.pw',
    credential,
    requireUserVerification: false,
  });

  assertEquals(verification.authenticationInfo.newCounter, 144);
  assertEquals(
    verification.authenticationInfo.credentialID,
    credential.id,
  );
  assertEquals(verification.authenticationInfo?.origin, assertionOrigin);
  assertEquals(verification.authenticationInfo?.rpID, 'dev.dontneeda.pw');
});

Deno.test('should throw when response challenge is not expected value', async () => {
  await assertRejects(
    () =>
      verifyAuthenticationResponse({
        response: assertionResponse,
        expectedChallenge: 'shouldhavebeenthisvalue',
        expectedOrigin: 'https://different.address',
        expectedRPID: 'dev.dontneeda.pw',
        credential,
      }),
    Error,
    'authentication response challenge',
  );
});

Deno.test('should throw when response origin is not expected value', async () => {
  await assertRejects(
    () =>
      verifyAuthenticationResponse({
        response: assertionResponse,
        expectedChallenge: assertionChallenge,
        expectedOrigin: 'https://different.address',
        expectedRPID: 'dev.dontneeda.pw',
        credential,
      }),
    Error,
    'authentication response origin',
  );
});

Deno.test('should throw when assertion type is not webauthn.create', async () => {
  const mockDecodeClientData = stub(
    _decodeClientDataJSONInternals,
    'stubThis',
    returnsNext([
      {
        origin: assertionOrigin,
        type: 'webauthn.badtype',
        challenge: assertionChallenge,
      },
    ]),
  );

  await assertRejects(
    () =>
      verifyAuthenticationResponse({
        response: assertionResponse,
        expectedChallenge: assertionChallenge,
        expectedOrigin: assertionOrigin,
        expectedRPID: 'dev.dontneeda.pw',
        credential,
      }),
    Error,
    'authentication response type',
  );

  mockDecodeClientData.restore();
});

Deno.test('should throw error if user was not present', async () => {
  const mockParseAuthData = stub(
    _parseAuthenticatorDataInternals,
    'stubThis',
    // @ts-ignore: Only return the values that matter
    returnsNext([
      {
        rpIdHash: await toHash(
          isoUint8Array.fromASCIIString('dev.dontneeda.pw'),
        ),
        flags: { up: false },
      },
    ]),
  );

  await assertRejects(
    () =>
      verifyAuthenticationResponse({
        response: assertionResponse,
        expectedChallenge: assertionChallenge,
        expectedOrigin: assertionOrigin,
        expectedRPID: 'dev.dontneeda.pw',
        credential,
      }),
    Error,
    'not present',
  );

  mockParseAuthData.restore();
});

Deno.test('should throw error if previous counter value is not less than in response', async () => {
  // This'll match the `counter` value in `assertionResponse`, simulating a potential replay attack
  const badCounter = 144;
  const badDevice = {
    ...credential,
    counter: badCounter,
  };

  await assertRejects(
    () =>
      verifyAuthenticationResponse({
        response: assertionResponse,
        expectedChallenge: assertionChallenge,
        expectedOrigin: assertionOrigin,
        expectedRPID: 'dev.dontneeda.pw',
        credential: badDevice,
        requireUserVerification: false,
      }),
    Error,
    'counter value',
  );
});

Deno.test('should throw error if assertion RP ID is unexpected value', async () => {
  const mockParseAuthData = stub(
    _parseAuthenticatorDataInternals,
    'stubThis',
    // @ts-ignore: Only return the values that matter
    returnsNext([
      {
        rpIdHash: await toHash(isoUint8Array.fromASCIIString('bad.url')),
        flags: 0,
      },
    ]),
  );

  await assertRejects(
    () =>
      verifyAuthenticationResponse({
        response: assertionResponse,
        expectedChallenge: assertionChallenge,
        expectedOrigin: assertionOrigin,
        expectedRPID: 'dev.dontneeda.pw',
        credential,
      }),
    Error,
    'RP ID',
  );

  mockParseAuthData.restore();
});

Deno.test('should not compare counters if both are 0', async () => {
  const verification = await verifyAuthenticationResponse({
    response: assertionFirstTimeUsedResponse,
    expectedChallenge: assertionFirstTimeUsedChallenge,
    expectedOrigin: assertionFirstTimeUsedOrigin,
    expectedRPID: 'dev.dontneeda.pw',
    credential: authenticatorFirstTimeUsed,
    requireUserVerification: false,
  });

  assertEquals(verification.verified, true);
});

Deno.test('should throw an error if user verification is required but user was not verified', async () => {
  const actualData = parseAuthenticatorData(
    isoBase64URL.toBuffer(assertionResponse.response.authenticatorData),
  );

  const mockParseAuthData = stub(
    _parseAuthenticatorDataInternals,
    'stubThis',
    // @ts-ignore: Only return the values that matter
    returnsNext([
      {
        ...actualData,
        flags: {
          up: true,
          uv: false,
        },
      },
    ]),
  );

  await assertRejects(
    () =>
      verifyAuthenticationResponse({
        response: assertionResponse,
        expectedChallenge: assertionChallenge,
        expectedOrigin: assertionOrigin,
        expectedRPID: 'dev.dontneeda.pw',
        credential,
        requireUserVerification: true,
      }),
    Error,
    'user could not be verified',
  );

  mockParseAuthData.restore();
});

// TODO: Get a real TPM authentication response in here
Deno.test('should verify TPM assertion', { ignore: true }, async () => {
  const expectedChallenge = 'dG90YWxseVVuaXF1ZVZhbHVlRXZlcnlBc3NlcnRpb24';
  const verification = await verifyAuthenticationResponse({
    response: {
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
    credential: {
      publicKey: isoBase64URL.toBuffer('BAEAAQ'),
      id: 'YJ8FMM-AmcUt73XPX341WXWd7ypBMylGjjhu0g3VzME',
      counter: 0,
    },
  });

  assert(verification.verified);
});

Deno.test('should support multiple possible origins', async () => {
  const verification = await verifyAuthenticationResponse({
    response: assertionResponse,
    expectedChallenge: assertionChallenge,
    expectedOrigin: ['https://simplewebauthn.dev', assertionOrigin],
    expectedRPID: 'dev.dontneeda.pw',
    credential,
    requireUserVerification: false,
  });

  assert(verification.verified);
  assertEquals(verification.authenticationInfo?.origin, assertionOrigin);
});

Deno.test('should throw an error if origin not in list of expected origins', async () => {
  await assertRejects(
    () =>
      verifyAuthenticationResponse({
        response: assertionResponse,
        expectedChallenge: assertionChallenge,
        expectedOrigin: ['https://simplewebauthn.dev', 'https://fizz.buzz'],
        expectedRPID: 'dev.dontneeda.pw',
        credential,
      }),
    Error,
    'Unexpected authentication response origin',
  );
});

Deno.test('should support multiple possible RP IDs', async () => {
  const verification = await verifyAuthenticationResponse({
    response: assertionResponse,
    expectedChallenge: assertionChallenge,
    expectedOrigin: assertionOrigin,
    expectedRPID: ['dev.dontneeda.pw', 'simplewebauthn.dev'],
    credential,
    requireUserVerification: false,
  });

  assert(verification.verified);
  assertEquals(verification.authenticationInfo?.rpID, 'dev.dontneeda.pw');
});

Deno.test('should throw an error if RP ID not in list of possible RP IDs', async () => {
  await assertRejects(
    () =>
      verifyAuthenticationResponse({
        response: assertionResponse,
        expectedChallenge: assertionChallenge,
        expectedOrigin: assertionOrigin,
        expectedRPID: ['simplewebauthn.dev'],
        credential,
      }),
    Error,
    'Unexpected RP ID',
  );
});

Deno.test('should throw an error if type not the expected type', async () => {
  await assertRejects(
    () =>
      verifyAuthenticationResponse({
        response: assertionResponse,
        expectedChallenge: assertionChallenge,
        expectedOrigin: assertionOrigin,
        // assertionResponse contains webauthn.get, this should produce an error
        expectedType: 'payment.get',
        expectedRPID: 'localhost',
        credential,
      }),
    Error,
    'Unexpected authentication response type',
  );
});

Deno.test('should throw an error if type not in list of expected types', async () => {
  await assertRejects(
    () =>
      verifyAuthenticationResponse({
        response: assertionResponse,
        expectedChallenge: assertionChallenge,
        expectedOrigin: assertionOrigin,
        // assertionResponse contains webauthn.get, this should produce an error
        expectedType: ['payment.get', 'something.get'],
        expectedRPID: 'localhost',
        credential,
      }),
    Error,
    'Unexpected authentication response type',
  );
});

Deno.test('should pass verification if custom challenge verifier returns true', async () => {
  const verification = await verifyAuthenticationResponse({
    response: {
      id:
        'AaIBxnYfL2pDWJmIii6CYgHBruhVvFGHheWamphVioG_TnEXxKA9MW4FWnJh21zsbmRpRJso9i2JmAtWOtXfVd4oXTgYVusXwhWWsA',
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
      const parsedChallenge: {
        actualChallenge: string;
        arbitraryData: string;
      } = JSON.parse(
        isoBase64URL.toUTF8String(challenge),
      );
      return parsedChallenge.actualChallenge ===
        'K3QxOjnVJLiGlnVEp5va5QJeMVWNf_7PYgutgbAtAUA';
    },
    expectedOrigin: 'http://localhost:8000',
    expectedRPID: 'localhost',
    credential: {
      id:
        'AaIBxnYfL2pDWJmIii6CYgHBruhVvFGHheWamphVioG_TnEXxKA9MW4FWnJh21zsbmRpRJso9i2JmAtWOtXfVd4oXTgYVusXwhWWsA',
      publicKey: isoBase64URL.toBuffer(
        'pQECAyYgASFYILTrxTUQv3X4DRM6L_pk65FSMebenhCx3RMsTKoBm-AxIlggEf3qk5552QLNSh1T1oQs7_2C2qysDwN4r4fCp52Hsqs',
      ),
      counter: 0,
    },
  });

  assert(verification.verified);
});

Deno.test('should fail verification if custom challenge verifier returns false', async () => {
  await assertRejects(
    () =>
      verifyAuthenticationResponse({
        response: assertionResponse,
        expectedChallenge: (challenge) => challenge === 'willNeverMatch',
        expectedOrigin: assertionOrigin,
        expectedRPID: 'dev.dontneeda.pw',
        credential,
      }),
    Error,
    'Custom challenge verifier returned false',
  );
});

Deno.test('should pass verification if custom challenge verifier returns a Promise that resolves with true', async () => {
  const verification = await verifyAuthenticationResponse({
    response: {
      id:
        'AaIBxnYfL2pDWJmIii6CYgHBruhVvFGHheWamphVioG_TnEXxKA9MW4FWnJh21zsbmRpRJso9i2JmAtWOtXfVd4oXTgYVusXwhWWsA',
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
      const parsedChallenge: {
        actualChallenge: string;
        arbitraryData: string;
      } = JSON.parse(
        isoBase64URL.toUTF8String(challenge),
      );
      return Promise.resolve(
        parsedChallenge.actualChallenge ===
          'K3QxOjnVJLiGlnVEp5va5QJeMVWNf_7PYgutgbAtAUA',
      );
    },
    expectedOrigin: 'http://localhost:8000',
    expectedRPID: 'localhost',
    credential: {
      id:
        'AaIBxnYfL2pDWJmIii6CYgHBruhVvFGHheWamphVioG_TnEXxKA9MW4FWnJh21zsbmRpRJso9i2JmAtWOtXfVd4oXTgYVusXwhWWsA',
      publicKey: isoBase64URL.toBuffer(
        'pQECAyYgASFYILTrxTUQv3X4DRM6L_pk65FSMebenhCx3RMsTKoBm-AxIlggEf3qk5552QLNSh1T1oQs7_2C2qysDwN4r4fCp52Hsqs',
      ),
      counter: 0,
    },
  });

  assert(verification.verified);
});

Deno.test('should fail verification if custom challenge verifier returns a Promise that resolves with false', async () => {
  await assertRejects(
    () =>
      verifyAuthenticationResponse({
        response: assertionResponse,
        expectedChallenge: (challenge) => Promise.resolve(challenge === 'willNeverMatch'),
        expectedOrigin: assertionOrigin,
        expectedRPID: 'dev.dontneeda.pw',
        credential,
      }),
    Error,
    'Custom challenge verifier returned false',
  );
});

Deno.test('should fail verification if custom challenge verifier returns a Promise that rejects', async () => {
  await assertRejects(
    () =>
      verifyAuthenticationResponse({
        response: assertionResponse,
        expectedChallenge: () => Promise.reject(new Error('rejected')),
        expectedOrigin: assertionOrigin,
        expectedRPID: 'dev.dontneeda.pw',
        credential,
      }),
    Error,
    'rejected',
  );
});

Deno.test('should return authenticator extension output', async () => {
  const verification = await verifyAuthenticationResponse({
    response: {
      response: {
        clientDataJSON:
          'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiaVpzVkN6dHJEVzdEMlVfR0hDSWxZS0x3VjJiQ3NCVFJxVlFVbkpYbjlUayIsIm9yaWdpbiI6ImFuZHJvaWQ6YXBrLWtleS1oYXNoOmd4N3NxX3B4aHhocklRZEx5ZkcwcHhLd2lKN2hPazJESlE0eHZLZDQzOFEiLCJhbmRyb2lkUGFja2FnZU5hbWUiOiJjb20uZmlkby5leGFtcGxlLmZpZG8yYXBpZXhhbXBsZSJ9',
        authenticatorData:
          'DXX8xWP9p3nbLjQ-6kiYiHWLeFSdSTpP2-oc2WqjHMSFAAAAAKFsZGV2aWNlUHViS2V5pWNkcGtYTaUBAgMmIAEhWCCZGqvtneQnGp7erYgG-dyW1tzNDEdiU6VRBInsg3m-WyJYIKCXPP3tu3nif-9O50gWc_szElBN3KVDTP0jQx1q0p7aY3NpZ1hHMEUCIElSbNKK72tOYhp9WTbStQSVL8CuIxOk8DV6r_-uqWR0AiEAnVE6yu-wsyx2Wq5v66jClGhe_2P_HL8R7PIQevT-uPhlbm9uY2VAZXNjb3BlQQBmYWFndWlkULk_2WHy5kYvsSKCACJH3ng',
        signature:
          'MEYCIQDlRuxY7cYre0sb3T6TovQdfYIUb72cRZYOQv_zS9wN_wIhAOvN-fwjtyIhWRceqJV4SX74-z6oALERbC7ohk8EdVPO',
        userHandle: 'b2FPajFxcmM4MWo3QkFFel9RN2lEakh5RVNlU2RLNDF0Sl92eHpQYWV5UQ==',
      },
      id: 'E_Pko4wN1BXE23S0ftN3eQ',
      rawId: 'E_Pko4wN1BXE23S0ftN3eQ',
      type: 'public-key',
      clientExtensionResults: {},
    },
    expectedOrigin: 'android:apk-key-hash:gx7sq_pxhxhrIQdLyfG0pxKwiJ7hOk2DJQ4xvKd438Q',
    expectedRPID: 'try-webauthn.appspot.com',
    expectedChallenge: 'iZsVCztrDW7D2U_GHCIlYKLwV2bCsBTRqVQUnJXn9Tk',
    credential: {
      id:
        'AaIBxnYfL2pDWJmIii6CYgHBruhVvFGHheWamphVioG_TnEXxKA9MW4FWnJh21zsbmRpRJso9i2JmAtWOtXfVd4oXTgYVusXwhWWsA',
      publicKey: isoBase64URL.toBuffer(
        'pQECAyYgASFYILTrxTUQv3X4DRM6L_pk65FSMebenhCx3RMsTKoBm-AxIlggEf3qk5552QLNSh1T1oQs7_2C2qysDwN4r4fCp52Hsqs',
      ),
      counter: 0,
    },
  });

  assertObjectMatch(
    verification.authenticationInfo!.authenticatorExtensionResults!,
    {
      devicePubKey: {
        dpk: isoUint8Array.fromHex(
          'A5010203262001215820991AABED9DE4271A9EDEAD8806F9DC96D6DCCD0C476253A5510489EC8379BE5B225820A0973CFDEDBB79E27FEF4EE7481673FB3312504DDCA5434CFD23431D6AD29EDA',
        ),
        sig: isoUint8Array.fromHex(
          '3045022049526CD28AEF6B4E621A7D5936D2B504952FC0AE2313A4F0357AAFFFAEA964740221009D513ACAEFB0B32C765AAE6FEBA8C294685EFF63FF1CBF11ECF2107AF4FEB8F8',
        ),
        nonce: isoUint8Array.fromHex(''),
        scope: isoUint8Array.fromHex('00'),
        aaguid: isoUint8Array.fromHex('B93FD961F2E6462FB12282002247DE78'),
      },
    },
  );
});

Deno.test('should return credential backup info', async () => {
  const verification = await verifyAuthenticationResponse({
    response: assertionResponse,
    expectedChallenge: assertionChallenge,
    expectedOrigin: assertionOrigin,
    expectedRPID: 'dev.dontneeda.pw',
    credential,
    requireUserVerification: false,
  });

  assertEquals(
    verification.authenticationInfo?.credentialDeviceType,
    'singleDevice',
  );
  assertEquals(verification.authenticationInfo?.credentialBackedUp, false);
});

Deno.test('should return user verified flag after successful auth', async () => {
  const verification = await verifyAuthenticationResponse({
    response: assertionResponse,
    expectedChallenge: assertionChallenge,
    expectedOrigin: assertionOrigin,
    expectedRPID: 'dev.dontneeda.pw',
    credential,
    requireUserVerification: false,
  });

  assertExists(verification.authenticationInfo?.userVerified);
  assertFalse(verification.authenticationInfo?.userVerified);
});

Deno.test('should verify when crossOrigin is true, topOrigin is missing, and expectedTopOrigin is not specified (Safari workaround)', async () => {
  const mockDecodeClientData = stub(
    _decodeClientDataJSONInternals,
    'stubThis',
    returnsNext([
      {
        type: 'webauthn.get',
        origin: assertionOrigin,
        challenge: assertionChallenge,
        crossOrigin: true,
      },
    ]),
  );

  try {
    const verification = await verifyAuthenticationResponse({
      response: assertionResponse,
      expectedChallenge: assertionChallenge,
      expectedOrigin: assertionOrigin,
      expectedRPID: 'dev.dontneeda.pw',
      credential,
      requireUserVerification: false,
    });

    assertEquals(verification.verified, true);
  } finally {
    mockDecodeClientData.restore();
  }
});

Deno.test('should verify when crossOrigin is true, topOrigin is missing, but expectedTopOrigin is specified (Safari workaround)', async () => {
  const mockDecodeClientData = stub(
    _decodeClientDataJSONInternals,
    'stubThis',
    returnsNext([
      {
        type: 'webauthn.get',
        origin: assertionOrigin,
        challenge: assertionChallenge,
        crossOrigin: true,
      },
    ]),
  );

  try {
    const verification = await verifyAuthenticationResponse({
      response: assertionResponse,
      expectedChallenge: assertionChallenge,
      expectedOrigin: assertionOrigin,
      expectedRPID: 'dev.dontneeda.pw',
      expectedTopOrigin: 'https://top.origin.com',
      credential,
      requireUserVerification: false,
    });

    assertEquals(verification.verified, true);
  } finally {
    mockDecodeClientData.restore();
  }
});

Deno.test('should verify when crossOrigin is true and topOrigin matches expectedTopOrigin (string)', async () => {
  const mockDecodeClientData = stub(
    _decodeClientDataJSONInternals,
    'stubThis',
    returnsNext([
      {
        type: 'webauthn.get',
        origin: assertionOrigin,
        challenge: assertionChallenge,
        crossOrigin: true,
        topOrigin: 'https://top.origin.com',
      },
    ]),
  );

  try {
    const verification = await verifyAuthenticationResponse({
      response: assertionResponse,
      expectedChallenge: assertionChallenge,
      expectedOrigin: assertionOrigin,
      expectedRPID: 'dev.dontneeda.pw',
      expectedTopOrigin: 'https://top.origin.com',
      credential,
      requireUserVerification: false,
    });

    assertEquals(verification.verified, true);
  } finally {
    mockDecodeClientData.restore();
  }
});

Deno.test('should throw when crossOrigin is true and topOrigin does not match expectedTopOrigin (string)', async () => {
  const mockDecodeClientData = stub(
    _decodeClientDataJSONInternals,
    'stubThis',
    returnsNext([
      {
        type: 'webauthn.get',
        origin: assertionOrigin,
        challenge: assertionChallenge,
        crossOrigin: true,
        topOrigin: 'https://wrong.top.origin.com',
      },
    ]),
  );

  try {
    await assertRejects(
      () =>
        verifyAuthenticationResponse({
          response: assertionResponse,
          expectedChallenge: assertionChallenge,
          expectedOrigin: assertionOrigin,
          expectedRPID: 'dev.dontneeda.pw',
          expectedTopOrigin: 'https://top.origin.com',
          credential,
        }),
      Error,
      'Unexpected cross-origin authentication response top origin of "https://wrong.top.origin.com", expected: https://top.origin.com',
    );
  } finally {
    mockDecodeClientData.restore();
  }
});

Deno.test('should verify when crossOrigin is true and topOrigin matches one of expectedTopOrigin (array)', async () => {
  const mockDecodeClientData = stub(
    _decodeClientDataJSONInternals,
    'stubThis',
    returnsNext([
      {
        type: 'webauthn.get',
        origin: assertionOrigin,
        challenge: assertionChallenge,
        crossOrigin: true,
        topOrigin: 'https://top.origin.com',
      },
    ]),
  );

  try {
    const verification = await verifyAuthenticationResponse({
      response: assertionResponse,
      expectedChallenge: assertionChallenge,
      expectedOrigin: assertionOrigin,
      expectedRPID: 'dev.dontneeda.pw',
      expectedTopOrigin: ['https://other.origin.com', 'https://top.origin.com'],
      credential,
      requireUserVerification: false,
    });

    assertEquals(verification.verified, true);
  } finally {
    mockDecodeClientData.restore();
  }
});

Deno.test('should throw when crossOrigin is true and topOrigin does not match any of expectedTopOrigin (array)', async () => {
  const mockDecodeClientData = stub(
    _decodeClientDataJSONInternals,
    'stubThis',
    returnsNext([
      {
        type: 'webauthn.get',
        origin: assertionOrigin,
        challenge: assertionChallenge,
        crossOrigin: true,
        topOrigin: 'https://wrong.top.origin.com',
      },
    ]),
  );

  try {
    await assertRejects(
      () =>
        verifyAuthenticationResponse({
          response: assertionResponse,
          expectedChallenge: assertionChallenge,
          expectedOrigin: assertionOrigin,
          expectedRPID: 'dev.dontneeda.pw',
          expectedTopOrigin: ['https://top.origin.com', 'https://other.origin.com'],
          credential,
        }),
      Error,
      'Unexpected cross-origin authentication response top origin of "https://wrong.top.origin.com", expected one of: https://top.origin.com, https://other.origin.com',
    );
  } finally {
    mockDecodeClientData.restore();
  }
});

Deno.test('should throw when crossOrigin is true but expectedTopOrigin is not specified', async () => {
  const mockDecodeClientData = stub(
    _decodeClientDataJSONInternals,
    'stubThis',
    returnsNext([
      {
        type: 'webauthn.get',
        origin: assertionOrigin,
        challenge: assertionChallenge,
        crossOrigin: true,
        topOrigin: 'https://top.origin.com',
      },
    ]),
  );

  try {
    await assertRejects(
      () =>
        verifyAuthenticationResponse({
          response: assertionResponse,
          expectedChallenge: assertionChallenge,
          expectedOrigin: assertionOrigin,
          expectedRPID: 'dev.dontneeda.pw',
          credential,
        }),
      Error,
      'Detected cross-origin authentication response from top origin of "https://top.origin.com", but a value for `expectedTopOrigin` was not specified when calling `verifyAuthenticationResponse()`',
    );
  } finally {
    mockDecodeClientData.restore();
  }
});

Deno.test('should throw when topOrigin is set despite crossOrigin being false', async () => {
  const mockDecodeClientData = stub(
    _decodeClientDataJSONInternals,
    'stubThis',
    returnsNext([
      {
        type: 'webauthn.get',
        origin: assertionOrigin,
        challenge: assertionChallenge,
        crossOrigin: false,
        topOrigin: 'https://some.top.origin.com',
      },
    ]),
  );

  try {
    await assertRejects(
      () =>
        verifyAuthenticationResponse({
          response: assertionResponse,
          expectedChallenge: assertionChallenge,
          expectedOrigin: assertionOrigin,
          expectedRPID: 'dev.dontneeda.pw',
          credential,
          requireUserVerification: false,
        }),
      Error,
      'Unexpected top origin of "https://some.top.origin.com" within a non-cross-origin authentication response. This error should be reported to the browser vendor as a WebAuthn specification violation with a link to https://w3c.github.io/webauthn/#dom-collectedclientdata-toporigin',
    );
  } finally {
    mockDecodeClientData.restore();
  }
});

Deno.test('should verify ML-DSA-44 authentication response', async () => {
  const options: Parameters<typeof verifyAuthenticationResponse>[0] = {
    response: {
      id: '-EM9FDFIdFVeqWdTycRjoZVN2ZS4vnVE-MBpg7k0pl4jpuqj4GnMCW3Wqlm2WWI2PQ',
      rawId: '-EM9FDFIdFVeqWdTycRjoZVN2ZS4vnVE-MBpg7k0pl4jpuqj4GnMCW3Wqlm2WWI2PQ',
      response: {
        authenticatorData: 'dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvAFAAAACA',
        clientDataJSON:
          'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiSmkxNTk3MWpTRVNhOWhhQ1VZYjdzX3BNaFY4RE5Od1lUOFdiNXpiRW8xNTFBYjdzX011VC1fTUlqbm91c2ZhRjJRM2VtRkF4N0drcFhrVFVtTWljVFEiLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0',
        signature:
          'e7L-Xli-2lj9ZlP2s26sbrvFGLkVrz74BZnDsLW-7HOhj7AcEl5Zgtm3VLvLtcrfqyKE0PTuFrswsikm7t6ddhxXphxWcSo4ggarl6ODQk8NdPCYoFhoK8qwpqKZKmJAl9xDsJE1HAudrWLgq_747JV4QmGLizK0_oJgGM7WLd5xVYvKsl14odBFjU_ZBCrjB0UHIMg8aAq1727yZnY1eiNeF_sEmci_pigYCo-MbxbHmQWPp-U75sGSPPfK0soN2-29_aIxRO4Fg8P37WrwVUrEFdG2PFNgAhcM-ljjyv3mkCfsLUiQNuS-a0cn6MeygREc2HBwE6ChS351-dpNTbkfnb-o1fA6suP1sh3-i7YZrEn9e2J7UZxIAEJPpmuKxYFA4Fj0lAGUhi3lvnkWPOnS8BUjPr5q5z5iEbyL4MokDP75G723Tyy-5L8u1pLmlSLiuwvuW5MBkEhjVVj0RpVSnCoqzwE9A9ZmqZx5wv5gQEi4hAA64mSoXGdUZ5EGkPGrrIDjGyIOrLjuHOSZ6hjyioZvMA1nCQJ76oaL5-Pn1FR1VTurI5ccTWrDAo5sHuo8uGjx9bsyy_aMT3Nzosu29PArTm0AkJFd7INXky0L9itCmhujSnali9zTO8UuwV0G8sZeB2BG4VZN2nkjT1Ib8VeBnSMTlIFVOI2JHlD9kePZuV3nCuAvK8j5qH5OPJoEeJzuxGHP2k7f0941kzyW9sjBaD90HEusVGGgST0qWigEKU3kKaO_Du5ZngcqlmKnnFVKXQk5mEV5nFs9ia76sKe9FKYUp_ZxsVFATcjXETW5GuXF1qIj0ZTCSmhn8V_cqEH29fQWyy9qxNa6kkKc4koZUP36B-h5yVawIDdfyjl-VueUvUyEunPv1EyqXQaf9bo-WThxD_5v3Bd2sYTOI__0PIsUvCASjZJMQU4jpwyXoR2EsLWDRD4fsAxLmdao0iXNxdlH0Ys2MqkXkkMbIylccEHkFjbm_VB5tPYQkFRqqRX13KUyYqqTpaT6MdD8IpltlzJxcNLd9mazUvOfSaf5ho2FFtv8TMubekKU8b92MoPQpjeS1DJ9y2pvMrtIiZP0Lm0WTeniN6luRfUN-4v5GU6FPajkOPLNV9OXJKLREhrA_SvbDldSF9RtWZOqIk1WeTlbnEWlejtwWFoLSScCSfExu6bu_vv9NKK-E8mTWF8_f4bCvlZQp58BEsTHrZuBiQzH34Z5wPeOZuuQlqbAquIS4_W6z_XmNW-d4FhIp2U3y9sYC7wpo1M7N7MB3HKwAliPVgsNHBRI4ZLZ-dL3FCyCMThKJqQMNrMcRif_Mm5Du--Atjn1UH2u2gAxiBA6IY7uSlSn-OJEO-m8qeif8zsdvVhXtJMxNAWZHhQ4QuRFgjuDgxy1nVuhGHdmXi6tseiiC2NQ9iqGuBRetexfz84R93RVSbKMkYlvBU1KPe8ARVf_N52C1KC9F2b3Uo5To9iD2lXShcsGkQkcAX5gjmhy4jrmTv5-pUJYAHa6A9Vorr59D7-Y-CVvVX59YJB9-kMT8wzHQdj2XimbcLKnS5Z4BKsMMEIt01LVkdHcBP9tKBQ20e-Kmf25wsUr9TqFa7ukQEhfLwgflIBbobAJoGKFC2_3fIKaEBuoAOoErASxPClLNAbBqG1JAdrAq9Ki3WC46aN4b-Q6ykfbk2azLAxOzFftJuhLWGLLCkOxbxjfaUrRJ51h8Dwrpy2xBT1qWurNnfFTrzScouK-R8G4SfsyaSiejiaLYLsWZVCcpeH_S8cqQuBFCMpQfxiPn2reOgMFhSzbdSDkzwUTQsjGq94QTs7bdS0LlyRb4OUa0s3szGSIa7n4vQ10uc9gzHlDxEqgaKSpPlVDyvZs58GC3PCZ2HJiiVbuc508_rV1xuydd7asPlyaOAMXImKPxp7d6rAGLbDOQOKS4U9sr6wKQVPnfPqg7TvmtuXTJS5Y_M6mutU7Bn8y6qmbjt5EtoETTSORHfx71ySMLZ8zxveJdsaNow6lfjvI0myk8oSDIucRar1j9G2m13B3K2Kr0URBweH6JkJz3Z7mYFTe09B6GMzIOcPoaYzzJP_PSrpuAfvb6V0AwVCX_HixF2qkCvcdrLyvGaGkkkYh32T2Renu7QWj8Wz06MvimWYCA4pB8SPJpjyw8mNZHOWJXgkI8hgD90O_rDF8mhEIMbDtfTZdOPjekS1a7-LNUGM6ajWLzDehU5YQBzTuGwgoPd2RV0E68iYR6QplHTmhh5vToa7eHvbQrYn8NUzJ6CP5YXcoxl7H9HsQ3AXDHmCtZ3e5p4FLV-Lz64_hVJWaTLOgHecFGAFqXMmnp1BtoKlzwbMnXaFMVaT1T7CkC_XZsoggQA1WFO3vFuXpnw4D6BPNGTmEZrEmINmfBVeFHB4SHDPJXDYX4wwTK8kgUpCHSI8ozIYFy0nw4uJqhkAYjXnvbEeCPsPkf7SPGS7xujgIdlYbtizeg-op2ZyI020Jt-hx2GogXRD_bsNcHaToWZ90fTI8M_Y1-F8iMJG4OnxinHlHnTj7R6wRuM2AZ4-Ov_yhd9w6yXenoKh56RReHCbYAvGCt3aDDyOrcX9WX7VePrBHH3C9ubCwj3PNcuP16or5ho6XRNlXC1s63J99dgi42FWatXeYdUvvcmK7fKxFZWSCXko-cArTT1KqgucxXg8wMk7gaGSwfb2j3pNt1hf4y5MOJQ-HbS0uhuywUbBiHBe8ns6FzUJpM4T8sNXAfbslBk1nIYU9BCMn1Veqw8puCYcwkjWJgxrKU_d2Jx0b8DKpIbbdFKkrdR4vAGRTJ74IgWPuk7wZTSWCddJAB4Q1PU1nbXO3MsxxzlQrWXY1jD9Zp3E69NEUss4qMTT6u5W-RG6RB6ge6sOt47l40v3IO-1LgsCwJtFyQzks0msArf0MSSQ9HreubNnjYqaMOqgUleX4-a0P8BhQwOhwt7C6zyGCnbcBiQx0RWAs0mvf-k5mgqn9Ij5mpGoGVV5L4OhBdY6pm51h7v02bgoWlzUzZHImgBhQtkx0jlBM9XeCIo4t8EQ4ZbqGmLsbj3CTu7KZbc9uQJkWyXSov2WWMvzZfOgCHbizXOGazd47v44BDRMXIiUmJzI1ZXiFkqPB0NftBw80ZnCHlpeq1Nzq8_QQHiM2R1SEsc_T1QQcSlJTVmBpdnqesbv9AAAAAAAAAAAAAAAAAAAAAAAAAAAAABMhLDo',
        userHandle: 'd2ViYXV0aG5pby1tbC1kc2EtNDQ',
      },
      type: 'public-key',
      clientExtensionResults: {},
    },
    expectedChallenge:
      'Ji15971jSESa9haCUYb7s_pMhV8DNNwYT8Wb5zbEo151Ab7s_MuT-_MIjnousfaF2Q3emFAx7GkpXkTUmMicTQ',
    expectedOrigin: 'https://webauthn.io',
    expectedRPID: 'webauthn.io',
    credential: {
      id: '',
      counter: 7,
      publicKey: isoBase64URL.toBuffer(
        'owEHAzgvIFkFIC4AIUrgARve17AEk0W30POluaL08p91eLXkktSjmAlmZdNTWhtUFj3wkseZEt4xpmWarG28Za86i7yq-B4df3uOuq3zQVTKOQUWJLWGJ3-wUUuyywPtkdgSqzQdcli6xMgwnVqh9r6FVL9Xp7x3kgjUVDqhux_k1D2d4ts2zqi1rUrSF6FNX139g3dd1VnUNQrMLdrwohR9CmE0fZ6Am4Df_OV2JxOrUEPzMFi5SeBcrU1oSj2lX_91gY179PO0wIOtTa1KzWvwOYa_KjOj9Ow16AtmsXrcpL-jYW4_bFn4kpT9G-vDG4qPFDpint62g0DDjEt7JrF288aIZXOpsbVmnjw2_O_5pFFvFpH32gD7_NdmvE6PSymNxPcTCnMzY3xv5wJXiEDhO21E85n78Oay4k7PzWHvzQxlJldIYw-9TfKZXqZa6sIbE-LyZj_Y2FV1Owd4WLvKCNcO-IIP3XFcZ7__XPZtAsBTJ5Z5w18jRnlMNKTygva-F2Ec65tA2skED9PnVyS_WjtZN5VjbhuU-D9DIDXEgUjitdcXWbCruDjxaBwjuDFXOI9cYdp4n-KWCZGJdX9QFHDGkvX6zDXupFrFV1q1JeKCayuMJjL3Z44AMF2UtjNODzhlviE8neX5NSfXdf36FWGFER6D6YCGGvooW8EBCx8OLPRNGGwoKBrEflr_ISYIdyw8-rDkAG0-bka_ulzfg8uTY8BXNu0HhqsteUPni4HlhUXMb0yI1DbLi5hTTkpBEBfmjzTJ8JMDe9sOOaqU2PrOzvIs5c7fx_VBqQZbF6amei2Y41okZJWwW0LWNvL2JQ_Yj9deHMczichCHWVX3uCL-SfPL3AaLeWLPjTAejU-H1Lnn2jWQeHtiRxBL1eleZNmJVqFbrgclcMXirM6rrmPrsbFe41fDF3Hm1KgcKkpZMPSICijfDCT4csVeLDxmsg9aDYwboxigOVHZa-zAmePLBZrPJIWDNEHNBG9CdEG-RfeshvnRbPerB1zLzA9jP-Jj55_Xd4igau4FEc7dLWgyn2b2Q3aMAaDnKCzEScd301WeuZtutm6flzqDPCUTJnoniUHuO__bALWkzIxe5rHW6wQ_wPBEX32bQNN-gtI6_yiw-UTwu3egro3tDp7ZzHkMSslF9FHD7divbmeEzsE8N4iOwO5kWFt2jY9VpjGXAhyCcGZtWU68SzllOpWzvuacFjlE5KZ_c4nHhYdaphJAjXvbkog-vGUwjffCXe9gQhIliwPzREtccZdgyLKiBAlypp0pwVKe6disU9-2kflk_BXPRf1PkBEqO41ySFZWLb6eSij9FrIXtPAo4RFmeKPLoYT-ce3gi8_XftVv7MDl9s0hoFlgh5vTh1xMdpxEt-6BxdesEF3zJycxNY4QFVkUKE78geXogQFz2QE7kW4ncTXjq4IydHOKX9Bp2P8uGcCJ6dzW3PFE-Zurf1klV-rkvT7xE-Tds7CPeWkrRr_Ckhn6rQ2Z3-Sjz5bgIRHiBnd0iZfm6ZgD77nVHY7ztaSmUQ7JWbeFSz0eoYExgXi7HfSdV77DlHxIjcNlrSh58SGWfkSwUVboOUJKy_B3EbBDeweqn1pf7QIjAJnYL7WiogmAku2UxEBQijtPAusmyhLf0_aTEFFc3zdGutHim3dzAKfJucy2aBm8ViQxY_U1N26WVO6sfui7dZVhqkQniZLCq8N_xqEMqWV6utksRHOvITvB_SqmeDacy2ZfiSogU8K5G0',
      ),
    },
  };

  if (denoSupportsPQC) {
    const verification = await verifyAuthenticationResponse(options);
    assert(verification.verified);
  } else {
    await assertRejects(
      () => verifyAuthenticationResponse(options),
      PQCNotSupportedError,
    );
  }
});

// Deno.test(
//   'should verify ML-DSA-65 authentication response',
//   /**
//    * ML-DSA is only supported in Deno v2.8.2+
//    */
//   { ignore: !runtimeIsDenoWithPQCSupport },
//   async () => {
//   const verification = await verifyAuthenticationResponse({});

//   assert(verification.verified);
// });

// Deno.test(
//   'should verify ML-DSA-87 authentication response',
//   /**
//    * ML-DSA is only supported in Deno v2.8.2+
//    */
//   { ignore: !runtimeIsDenoWithPQCSupport },
//   async () => {
//   const verification = await verifyAuthenticationResponse({});

//   assert(verification.verified);
// });

/**
 * Assertion examples below
 */

const assertionResponse: AuthenticationResponseJSON = {
  id: 'KEbWNCc7NgaYnUyrNeFGX9_3Y-8oJ3KwzjnaiD1d1LVTxR7v3CaKfCz2Vy_g_MHSh7yJ8yL0Pxg6jo_o0hYiew',
  rawId: 'KEbWNCc7NgaYnUyrNeFGX9_3Y-8oJ3KwzjnaiD1d1LVTxR7v3CaKfCz2Vy_g_MHSh7yJ8yL0Pxg6jo_o0hYiew',
  response: {
    authenticatorData: 'PdxHEOnAiLIp26idVjIguzn3Ipr_RlsKZWsa-5qK-KABAAAAkA==',
    clientDataJSON: 'eyJjaGFsbGVuZ2UiOiJkRzkwWVd4c2VWVnVhWEYxWlZaaGJIVmxSWFpsY25sVWFXMWwiLCJj' +
      'bGllbnRFeHRlbnNpb25zIjp7fSwiaGFzaEFsZ29yaXRobSI6IlNIQS0yNTYiLCJvcmlnaW4iOiJodHRwczovL2Rldi5k' +
      'b250bmVlZGEucHciLCJ0eXBlIjoid2ViYXV0aG4uZ2V0In0=',
    signature: 'MEUCIQDYXBOpCWSWq2Ll4558GJKD2RoWg958lvJSB_GdeokxogIgWuEVQ7ee6AswQY0OsuQ6y8Ks6' +
      'jhd45bDx92wjXKs900=',
  },
  clientExtensionResults: {},
  type: 'public-key',
};
const assertionChallenge = isoBase64URL.fromUTF8String(
  'totallyUniqueValueEveryTime',
);
const assertionOrigin = 'https://dev.dontneeda.pw';

const credential: WebAuthnCredential = {
  publicKey: isoBase64URL.toBuffer(
    'pQECAyYgASFYIIheFp-u6GvFT2LNGovf3ZrT0iFVBsA_76rRysxRG9A1Ilgg8WGeA6hPmnab0HAViUYVRkwTNcN77QBf_RR0dv3lIvQ',
  ),
  id: 'KEbWNCc7NgaYnUyrNeFGX9_3Y-8oJ3KwzjnaiD1d1LVTxR7v3CaKfCz2Vy_g_MHSh7yJ8yL0Pxg6jo_o0hYiew',
  counter: 143,
};

/**
 * Represented a device that's being used on the website for the first time
 */
const assertionFirstTimeUsedResponse: AuthenticationResponseJSON = {
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
const assertionFirstTimeUsedChallenge = isoBase64URL.fromUTF8String(
  'totallyUniqueValueEveryAssertion',
);
const assertionFirstTimeUsedOrigin = 'https://dev.dontneeda.pw';
const authenticatorFirstTimeUsed: WebAuthnCredential = {
  publicKey: isoBase64URL.toBuffer(
    'pQECAyYgASFYIGmaxR4mBbukc2QhtW2ldhAAd555r-ljlGQN8MbcTnPPIlgg9CyUlE-0AB2fbzZbNgBvJuRa7r6o2jPphOmtyNPR_kY',
  ),
  id: 'wSisR0_4hlzw3Y1tj4uNwwifIhRa-ZxWJwWbnfror0pVK9qPdBPO5pW3gasPqn6wXHb0LNhXB_IrA1nFoSQJ9A',
  counter: 0,
};
