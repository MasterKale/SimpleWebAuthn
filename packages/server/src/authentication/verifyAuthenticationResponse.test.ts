import {
  assert,
  assertEquals,
  assertExists,
  assertRejects,
} from 'https://deno.land/std@0.198.0/assert/mod.ts';
import { returnsNext, stub } from 'https://deno.land/std@0.198.0/testing/mock.ts';

import { verifyAuthenticationResponse } from './verifyAuthenticationResponse.ts';

import { _decodeClientDataJSONInternals } from '../helpers/decodeClientDataJSON.ts';
import {
  _parseAuthenticatorDataInternals,
  parseAuthenticatorData,
} from '../helpers/parseAuthenticatorData.ts';
import { toHash } from '../helpers/toHash.ts';
import { AuthenticationResponseJSON, AuthenticatorDevice } from '../deps.ts';
import { isoBase64URL, isoUint8Array } from '../helpers/iso/index.ts';
import { assertObjectMatch } from 'https://deno.land/std@0.198.0/assert/assert_object_match.ts';
import { assertFalse } from 'https://deno.land/std@0.198.0/assert/assert_false.ts';

Deno.test('should verify an assertion response', async () => {
  const verification = await verifyAuthenticationResponse({
    response: assertionResponse,
    expectedChallenge: assertionChallenge,
    expectedOrigin: assertionOrigin,
    expectedRPID: 'dev.dontneeda.pw',
    authenticator: authenticator,
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
    authenticator: authenticator,
    requireUserVerification: false,
  });

  assertEquals(verification.authenticationInfo.newCounter, 144);
  assertEquals(
    verification.authenticationInfo.credentialID,
    authenticator.credentialID,
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
        authenticator: authenticator,
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
        authenticator: authenticator,
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
        authenticator: authenticator,
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
        authenticator: authenticator,
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
    ...authenticator,
    counter: badCounter,
  };

  await assertRejects(
    () =>
      verifyAuthenticationResponse({
        response: assertionResponse,
        expectedChallenge: assertionChallenge,
        expectedOrigin: assertionOrigin,
        expectedRPID: 'dev.dontneeda.pw',
        authenticator: badDevice,
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
        authenticator: authenticator,
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
    authenticator: authenticatorFirstTimeUsed,
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
        authenticator: authenticator,
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
  // jest.spyOn(isoBase64URL, "toString").mockReturnValueOnce(expectedChallenge);
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
    authenticator: {
      credentialPublicKey: isoBase64URL.toBuffer('BAEAAQ'),
      credentialID: isoBase64URL.toBuffer(
        'YJ8FMM-AmcUt73XPX341WXWd7ypBMylGjjhu0g3VzME',
      ),
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
    authenticator: authenticator,
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
        authenticator: authenticator,
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
    authenticator: authenticator,
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
        authenticator: authenticator,
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
        authenticator: authenticator,
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
        authenticator: authenticator,
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
        isoBase64URL.toString(challenge),
      );
      return parsedChallenge.actualChallenge ===
        'K3QxOjnVJLiGlnVEp5va5QJeMVWNf_7PYgutgbAtAUA';
    },
    expectedOrigin: 'http://localhost:8000',
    expectedRPID: 'localhost',
    authenticator: {
      credentialID: isoBase64URL.toBuffer(
        'AaIBxnYfL2pDWJmIii6CYgHBruhVvFGHheWamphVioG_TnEXxKA9MW4FWnJh21zsbmRpRJso9i2JmAtWOtXfVd4oXTgYVusXwhWWsA',
      ),
      credentialPublicKey: isoBase64URL.toBuffer(
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
        authenticator: authenticator,
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
        isoBase64URL.toString(challenge),
      );
      return Promise.resolve(
        parsedChallenge.actualChallenge ===
          'K3QxOjnVJLiGlnVEp5va5QJeMVWNf_7PYgutgbAtAUA',
      );
    },
    expectedOrigin: 'http://localhost:8000',
    expectedRPID: 'localhost',
    authenticator: {
      credentialID: isoBase64URL.toBuffer(
        'AaIBxnYfL2pDWJmIii6CYgHBruhVvFGHheWamphVioG_TnEXxKA9MW4FWnJh21zsbmRpRJso9i2JmAtWOtXfVd4oXTgYVusXwhWWsA',
      ),
      credentialPublicKey: isoBase64URL.toBuffer(
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
        authenticator: authenticator,
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
        authenticator: authenticator,
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
    authenticator: {
      credentialID: isoBase64URL.toBuffer(
        'AaIBxnYfL2pDWJmIii6CYgHBruhVvFGHheWamphVioG_TnEXxKA9MW4FWnJh21zsbmRpRJso9i2JmAtWOtXfVd4oXTgYVusXwhWWsA',
      ),
      credentialPublicKey: isoBase64URL.toBuffer(
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
    authenticator: authenticator,
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
    authenticator: authenticator,
    requireUserVerification: false,
  });

  assertExists(verification.authenticationInfo?.userVerified);
  assertFalse(verification.authenticationInfo?.userVerified);
});

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
const assertionChallenge = isoBase64URL.fromString(
  'totallyUniqueValueEveryTime',
);
const assertionOrigin = 'https://dev.dontneeda.pw';

const authenticator: AuthenticatorDevice = {
  credentialPublicKey: isoBase64URL.toBuffer(
    'pQECAyYgASFYIIheFp-u6GvFT2LNGovf3ZrT0iFVBsA_76rRysxRG9A1Ilgg8WGeA6hPmnab0HAViUYVRkwTNcN77QBf_RR0dv3lIvQ',
  ),
  credentialID: isoBase64URL.toBuffer(
    'KEbWNCc7NgaYnUyrNeFGX9_3Y-8oJ3KwzjnaiD1d1LVTxR7v3CaKfCz2Vy_g_MHSh7yJ8yL0Pxg6jo_o0hYiew',
  ),
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
const assertionFirstTimeUsedChallenge = isoBase64URL.fromString(
  'totallyUniqueValueEveryAssertion',
);
const assertionFirstTimeUsedOrigin = 'https://dev.dontneeda.pw';
const authenticatorFirstTimeUsed: AuthenticatorDevice = {
  credentialPublicKey: isoBase64URL.toBuffer(
    'pQECAyYgASFYIGmaxR4mBbukc2QhtW2ldhAAd555r-ljlGQN8MbcTnPPIlgg9CyUlE-0AB2fbzZbNgBvJuRa7r6o2jPphOmtyNPR_kY',
  ),
  credentialID: isoBase64URL.toBuffer(
    'wSisR0_4hlzw3Y1tj4uNwwifIhRa-ZxWJwWbnfror0pVK9qPdBPO5pW3gasPqn6wXHb0LNhXB_IrA1nFoSQJ9A',
  ),
  counter: 0,
};
