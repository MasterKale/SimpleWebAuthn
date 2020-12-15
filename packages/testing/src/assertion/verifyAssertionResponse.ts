import { VerifyAssertionResponseOptions, VerifiedAssertion } from '@simplewebauthn/server';
import base64url from 'base64url';

interface TestingData {
  options: VerifyAssertionResponseOptions;
  result: VerifiedAssertion;
}

export default class VerifyAssertionResponseTestingData {
  static default(): TestingData {
    return {
      options: {
        credential: assertionResponse,
        expectedChallenge: assertionChallenge,
        expectedOrigin: assertionOrigin,
        expectedRPID: 'dev.dontneeda.pw',
        authenticator: authenticator,
      },
      result: {
        verified: true,
        authenticatorInfo: { counter: 144, base64CredentialID: authenticator.credentialID },
      },
    };
  }
}

const assertionResponse = {
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
  getClientExtensionResults: () => ({}),
  type: 'public-key',
};
const assertionChallenge = base64url.encode('totallyUniqueValueEveryTime');
const assertionOrigin = 'https://dev.dontneeda.pw';

const authenticator = {
  publicKey:
    'pQECAyYgASFYIIheFp-u6GvFT2LNGovf3ZrT0iFVBsA_76rRysxRG9A1Ilgg8WGeA6hPmnab0HAViUYVRkwTNcN77QBf_RR0dv3lIvQ',
  credentialID:
    'KEbWNCc7NgaYnUyrNeFGX9_3Y-8oJ3KwzjnaiD1d1LVTxR7v3CaKfCz2Vy_g_MHSh7yJ8yL0Pxg6jo_o0hYiew',
  counter: 143,
};
