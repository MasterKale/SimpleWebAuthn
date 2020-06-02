import base64url from 'base64url';
import {
  AssertionCredentialJSON,
  AuthenticatorDevice,
} from '@simplewebauthn/typescript-types';

import decodeClientDataJSON from '../helpers/decodeClientDataJSON';
import toHash from '../helpers/toHash';
import convertASN1toPEM from '../helpers/convertASN1toPEM';
import verifySignature from '../helpers/verifySignature';
import parseAuthenticatorData from '../helpers/parseAuthenticatorData';

/**
 * Verify that the user has legitimately completed the login process
 *
 * @param response Authenticator assertion response with base64url-encoded values
 * @param expectedChallenge The random value provided to generateAssertionOptions for the
 * authenticator to sign
 * @param expectedOrigin Expected URL of website assertion should have occurred on
 */
export default function verifyAssertionResponse(
  credential: AssertionCredentialJSON,
  expectedChallenge: string,
  expectedOrigin: string,
  authenticator: AuthenticatorDevice,
): VerifiedAssertion {
  const { response } = credential;
  const clientDataJSON = decodeClientDataJSON(response.clientDataJSON);

  const { type, origin, challenge } = clientDataJSON;

  if (!expectedOrigin.startsWith('https://')) {
    expectedOrigin = `https://${expectedOrigin}`;
  }

  if (challenge !== expectedChallenge) {
    throw new Error(
      `Unexpected assertion challenge "${challenge}", expected "${expectedChallenge}"`,
    );
  }

  // Check that the origin is our site
  if (origin !== expectedOrigin) {
    throw new Error(`Unexpected assertion origin "${origin}", expected "${expectedOrigin}"`);
  }

  // Make sure we're handling an assertion
  if (type !== 'webauthn.get') {
    throw new Error(`Unexpected assertion type: ${type}`);
  }

  const authDataBuffer = base64url.toBuffer(response.authenticatorData);
  const authDataStruct = parseAuthenticatorData(authDataBuffer);
  const { flags, counter } = authDataStruct;

  if (!flags.up) {
    throw new Error('User not present during assertion');
  }

  if (counter <= authenticator.counter) {
    // Error out when the counter in the DB is greater than or equal to the counter in the
    // dataStruct. It's related to how the authenticator maintains the number of times its been
    // used for this client. If this happens, then someone's somehow increased the counter
    // on the device without going through this site
    throw new Error(
      `Response counter value ${counter} was lower than expected ${authenticator.counter}`,
    );
  }

  const { rpIdHash, flagsBuf, counterBuf } = authDataStruct;

  const clientDataHash = toHash(base64url.toBuffer(response.clientDataJSON));
  const signatureBase = Buffer.concat([rpIdHash, flagsBuf, counterBuf, clientDataHash]);

  const publicKey = convertASN1toPEM(base64url.toBuffer(authenticator.publicKey));
  const signature = base64url.toBuffer(response.signature);

  const toReturn = {
    verified: verifySignature(signature, signatureBase, publicKey),
    authenticatorInfo: {
      counter,
      base64CredentialID: credential.id,
    },
  };

  return toReturn;
}

/**
 * Result of assertion verification
 *
 * @param verified If the assertion response could be verified
 * @param authenticatorInfo.base64CredentialID The ID of the authenticator used during assertion.
 * Should be used to identify which DB authenticator entry needs its `counter` updated to the value
 * below
 * @param authenticatorInfo.counter The number of times the authenticator identified above reported
 * it has been used. **Should be kept in a DB for later reference to help prevent replay attacks!**
 */
export type VerifiedAssertion = {
  verified: boolean;
  authenticatorInfo: {
    counter: number;
    base64CredentialID: string;
  };
};
