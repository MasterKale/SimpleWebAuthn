import base64url from 'base64url';
import {
  AuthenticatorAssertionResponseJSON,
  AuthenticatorDevice,
  VerifiedAssertion,
} from "@webauthntine/typescript-types";

import decodeClientDataJSON from "@helpers/decodeClientDataJSON";

import toHash from '@helpers/toHash';
import convertASN1toPEM from '@helpers/convertASN1toPEM';
import verifySignature from '@helpers/verifySignature';
import parseAuthenticatorData from '@helpers/parseAuthenticatorData';

/**
 * Verify that the user has legitimately completed the login process
 *
 * @param response Authenticator assertion response with base64-encoded values
 * @param expectedChallenge The random value provided to generateAssertionOptions for the
 * authenticator to sign
 * @param expectedOrigin Expected URL of website assertion should have occurred on
 */
export default function verifyAssertionResponse(
  response: AuthenticatorAssertionResponseJSON,
  expectedChallenge: string,
  expectedOrigin: string,
  authenticator: AuthenticatorDevice,
): VerifiedAssertion {
  const { base64AuthenticatorData, base64ClientDataJSON, base64Signature } = response;
  const clientDataJSON = decodeClientDataJSON(base64ClientDataJSON);

  const { type, origin, challenge } = clientDataJSON;

  if (!expectedOrigin.startsWith('https://')) {
    expectedOrigin = `https://${expectedOrigin}`;
  }

  if (challenge !== expectedChallenge) {
    throw new Error(
      `Unexpected assertion challenge "${challenge}", expected "${expectedChallenge}"`
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

  const authDataBuffer = base64url.toBuffer(base64AuthenticatorData);
  const authDataStruct = parseAuthenticatorData(authDataBuffer);
  const { flags, counter } = authDataStruct;

  if (!(flags.up)) {
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

  const {
    rpIdHash,
    flagsBuf,
    counterBuf,
  } = authDataStruct;

  const clientDataHash = toHash(base64url.toBuffer(base64ClientDataJSON));
  const signatureBase = Buffer.concat([
    rpIdHash,
    flagsBuf,
    counterBuf,
    clientDataHash,
  ]);

  const publicKey = convertASN1toPEM(base64url.toBuffer(authenticator.base64PublicKey));
  const signature = base64url.toBuffer(base64Signature);

  const toReturn = {
    verified: verifySignature(signature, signatureBase, publicKey),
    authenticatorInfo: {
      counter,
      base64CredentialID: response.base64CredentialID,
    },
  };

  return toReturn;
}
