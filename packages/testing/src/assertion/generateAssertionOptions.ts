import { PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/typescript-types';
import { GenerateAssertionOptions } from '@simplewebauthn/server';
import base64url from 'base64url';

interface TestingData {
  options: GenerateAssertionOptions;
  result: PublicKeyCredentialRequestOptionsJSON;
}

export default class GenerateAssertionOptionsTestingData {
  static default(): TestingData {
    const challenge = 'totallyUniqueValueEveryTime';
    return {
      options: {
        challenge,
      },
      result: {
        challenge: base64url.encode(challenge),
        allowCredentials: undefined,
        extensions: undefined,
        rpId: undefined,
        timeout: 60000,
        userVerification: undefined,
      },
    };
  }

  static withAllowCredentials(): TestingData {
    const challenge = 'totallyUniqueValueEveryTime';
    return {
      options: {
        allowCredentials: [
          {
            id:
              'KEbWNCc7NgaYnUyrNeFGX9_3Y-8oJ3KwzjnaiD1d1LVTxR7v3CaKfCz2Vy_g_MHSh7yJ8yL0Pxg6jo_o0hYiew',
            type: 'public-key',
            transports: ['usb', 'nfc', 'internal'],
          },
        ],
        challenge,
      },
      result: {
        challenge: base64url.encode(challenge),
        allowCredentials: [
          {
            id:
              'KEbWNCc7NgaYnUyrNeFGX9_3Y-8oJ3KwzjnaiD1d1LVTxR7v3CaKfCz2Vy_g_MHSh7yJ8yL0Pxg6jo_o0hYiew',
            type: 'public-key',
            transports: ['usb', 'nfc', 'internal'],
          },
        ],
        timeout: 60000,
      },
    };
  }
}
