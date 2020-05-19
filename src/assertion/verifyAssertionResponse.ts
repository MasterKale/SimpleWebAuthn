import base64url from 'base64url';

import {
  EncodedAuthenticatorAssertionResponse,
  U2F_USER_PRESENTED,
  AuthenticatorDevice,
  VerifiedAssertion,
} from "@types";
import decodeClientDataJSON from "@helpers/decodeClientDataJSON";

import parseAssertionAuthData from './parseAssertionAuthData';
import toHash from '@helpers/toHash';
import convertASN1toPEM from '@helpers/convertASN1toPEM';
import verifySignature from '@helpers/verifySignature';

/**
 * Verify that the user has legitimately completed the login process
 *
 * @param response Authenticator attestation response with base64-encoded values
 * @param expectedOrigin Expected URL of website attestation should have occurred on
 */
export default function verifyAssertionResponse(
  response: EncodedAuthenticatorAssertionResponse,
  expectedOrigin: string,
  authenticator: AuthenticatorDevice,
): VerifiedAssertion {
  const { base64AuthenticatorData, base64ClientDataJSON, base64Signature } = response;
  const clientDataJSON = decodeClientDataJSON(base64ClientDataJSON);

  console.debug('decodedClientDataJSON:', clientDataJSON);

  const { type, origin } = clientDataJSON;

  // Check that the origin is our site
  if (origin !== expectedOrigin) {
    console.error('client origin did not equal our origin');
    console.debug('expectedOrigin:', expectedOrigin);
    console.debug('assertion\'s origin:', origin);
    throw new Error('Assertion origin was an unexpected value');
  }

  // Make sure we're handling an assertion
  if (type !== 'webauthn.get') {
    console.error('type did not equal "webauthn.get"');
    console.debug('attestation\'s type:', type);
    throw new Error('Attestation type was an unexpected value');
  }

  const authDataBuffer = base64url.toBuffer(base64AuthenticatorData);
  const authData = parseAssertionAuthData(authDataBuffer);
  console.log('parsed authData:', authData);

  if (!(authData.flags & U2F_USER_PRESENTED)) {
    throw new Error('User was NOT present during authentication!');
  }

  const {
    rpIdHash,
    flagsBuf,
    counterBuf,
    counter,
  } = authData;

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

  if (toReturn.verified) {
    if (counter <= authenticator.counter) {
      // Error out when the counter in the DB is greater than or equal to the counter in the
      // dataStruct. It's related to how the authenticator maintains the number of times its been
      // used for this client. If this happens, then someone's somehow increased the counter
      // on the device without going through this site
      throw new Error(`Device's counter ${counter} isn't greater than ${authenticator.counter}!`);
    }
  }

  return toReturn;
}
