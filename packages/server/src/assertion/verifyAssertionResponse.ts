import base64url from 'base64url';
import {
  AuthenticatorAssertionResponseJSON,
  U2F_USER_PRESENTED,
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
 * @param response Authenticator attestation response with base64-encoded values
 * @param expectedOrigin Expected URL of website attestation should have occurred on
 */
export default function verifyAssertionResponse(
  response: AuthenticatorAssertionResponseJSON,
  expectedOrigin: string,
  authenticator: AuthenticatorDevice,
): VerifiedAssertion {
  const { base64AuthenticatorData, base64ClientDataJSON, base64Signature } = response;
  const clientDataJSON = decodeClientDataJSON(base64ClientDataJSON);

  const { type, origin } = clientDataJSON;

  // Check that the origin is our site
  if (origin !== expectedOrigin) {
    throw new Error(`Unexpected assertion origin: ${origin}`);
  }

  // Make sure we're handling an assertion
  if (type !== 'webauthn.get') {
    throw new Error(`Unexpected assertion type: ${type}`);
  }

  const authDataBuffer = base64url.toBuffer(base64AuthenticatorData);
  const authDataStruct = parseAuthenticatorData(authDataBuffer);

  if (!(authData.flags & U2F_USER_PRESENTED)) {
    throw new Error('User was NOT present during assertion!');
  }

  const {
    rpIdHash,
    flagsBuf,
    counterBuf,
    counter,
  } = authData;

  if (counter <= authenticator.counter) {
    // Error out when the counter in the DB is greater than or equal to the counter in the
    // dataStruct. It's related to how the authenticator maintains the number of times its been
    // used for this client. If this happens, then someone's somehow increased the counter
    // on the device without going through this site
    throw new Error(
      `Response counter value ${counter} was lower than expected ${authenticator.counter}`,
    );
  }

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
  };

  return toReturn;
}
