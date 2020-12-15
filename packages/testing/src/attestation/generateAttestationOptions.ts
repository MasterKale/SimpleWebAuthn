import { PublicKeyCredentialCreationOptionsJSON } from '@simplewebauthn/typescript-types';
import { GenerateAttestationOptions } from '@simplewebauthn/server';
import base64url from 'base64url';

interface TestingData {
  options: GenerateAttestationOptions;
  result: PublicKeyCredentialCreationOptionsJSON;
}

export default class GenerateAssertionOptionsTestingData {
  static default(): TestingData {
    const rpName = 'SimpleWebAuthn';
    const rpID = 'dev.dontneeda.pw';
    const challenge = 'totallyUniqueValueEveryTime';
    const userID = '1234';
    const userName = 'usernameHere';
    const timeout = 60000;
    const attestationType = 'indirect';
    return {
      options: {
        rpName,
        rpID,
        challenge,
        userID,
        userName,
        timeout,
        attestationType,
      },
      result: {
        // Challenge, base64url-encoded
        challenge: base64url.encode(challenge),
        rp: {
          name: rpName,
          id: rpID,
        },
        user: {
          id: userID,
          name: userName,
          displayName: userName,
        },
        pubKeyCredParams: [
          { alg: -7, type: 'public-key' },
          { alg: -8, type: 'public-key' },
          { alg: -36, type: 'public-key' },
          { alg: -37, type: 'public-key' },
          { alg: -38, type: 'public-key' },
          { alg: -39, type: 'public-key' },
          { alg: -257, type: 'public-key' },
          { alg: -258, type: 'public-key' },
          { alg: -259, type: 'public-key' },
        ],
        timeout,
        attestation: attestationType,
        excludeCredentials: [],
        authenticatorSelection: {
          requireResidentKey: false,
          userVerification: 'preferred',
        },
      },
    };
  }
}
