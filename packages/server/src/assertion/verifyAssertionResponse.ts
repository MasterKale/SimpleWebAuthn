import base64url from 'base64url';

import decodeClientDataJSON from '../helpers/decodeClientDataJSON';
import toHash from '../helpers/toHash';
import convertPublicKeyToPEM from '../helpers/convertPublicKeyToPEM';
import verifySignature from '../helpers/verifySignature';
import parseAuthenticatorData from '../helpers/parseAuthenticatorData';
import isBase64URLString from '../helpers/isBase64URLString';
import { VerifyAssertionOptions } from './options';
import reducePromise from '../helpers/reducePromise';

/**
 * Verify that the user has legitimately completed the login process
 *
 * **Options:**
 *
 * @param credential Authenticator credential returned by browser's `startAssertion()`
 * @param expectedChallenge The base64url-encoded `options.challenge` returned by
 * `generateAssertionOptions()` if serverSecret not used
 * @param signedChallenge Server signed challenge sent back from the device originally emitted by the generateAssertionOptions
 * ONLY if serverSecret was used in generateAssertionOptions (allow to avoid storing challenge into the DB)
 * @param expectedOrigin Website URL that the attestation should have occurred on
 * @param expectedRPID RP ID that was specified in the attestation options
 * @param authenticator An internal {@link AuthenticatorDevice} matching the credential's ID
 * @param fidoUserVerification (Optional) The value specified for `userVerification` when calling
 * `generateAssertionOptions()`. Activates FIDO-specific user presence and verification checks.
 * Omitting this value defaults verification to a WebAuthn-specific user presence requirement.
 */
export default async function verifyAssertionResponse(
  options: VerifyAssertionOptions,
): Promise<VerifiedAssertion> {
  if (options.adapters) {
    options = await reducePromise(
      options.adapters,
      (acc, adapter) => adapter.verifyAssert(acc),
      options,
    );
  }
  const {
    credential,
    authenticator,
    fidoUserVerification,
    expectedChallenge,
    expectedOrigin,
    expectedRPID,
  } = options;

  if (!expectedRPID) throw new Error('Missing expectedRPID check options/adapters');
  if (!expectedOrigin) throw new Error('Missing expectedOrigin check options/adapters');
  if (!expectedChallenge) throw new Error('Missing expectedChallenge check options/adapters');

  const { id, rawId, type: credentialType, response } = credential;

  // Ensure credential specified an ID
  if (!id) {
    throw new Error('Missing credential ID');
  }

  // Ensure ID is base64url-encoded
  if (id !== rawId) {
    throw new Error('Credential ID was not base64url-encoded');
  }

  // Make sure credential type is public-key
  if (credentialType !== 'public-key') {
    throw new Error(`Unexpected credential type ${credentialType}, expected "public-key"`);
  }

  if (!response) {
    throw new Error('Credential missing response');
  }

  if (typeof response?.clientDataJSON !== 'string') {
    throw new Error('Credential response clientDataJSON was not a string');
  }

  const clientDataJSON = decodeClientDataJSON(response.clientDataJSON);

  const { type, origin, challenge, tokenBinding } = clientDataJSON;

  // Make sure we're handling an assertion
  if (type !== 'webauthn.get') {
    throw new Error(`Unexpected assertion type: ${type}`);
  }

  // Ensure the device provided the challenge we gave it
  if (challenge !== expectedChallenge) {
    throw new Error(
      `Unexpected assertion challenge "${challenge}", expected "${expectedChallenge}"`,
    );
  }

  // Check that the origin is our site
  if (origin !== expectedOrigin) {
    throw new Error(`Unexpected assertion origin "${origin}", expected "${expectedOrigin}"`);
  }

  if (!isBase64URLString(response.authenticatorData)) {
    throw new Error('Credential response authenticatorData was not a base64url string');
  }

  if (!isBase64URLString(response.signature)) {
    throw new Error('Credential response signature was not a base64url string');
  }

  if (response.userHandle && typeof response.userHandle !== 'string') {
    throw new Error('Credential response userHandle was not a string');
  }

  if (tokenBinding) {
    if (typeof tokenBinding !== 'object') {
      throw new Error('ClientDataJSON tokenBinding was not an object');
    }

    if (['present', 'supported', 'notSupported'].indexOf(tokenBinding.status) < 0) {
      throw new Error(`Unexpected tokenBinding status ${tokenBinding.status}`);
    }
  }

  const authDataBuffer = base64url.toBuffer(response.authenticatorData);
  const parsedAuthData = parseAuthenticatorData(authDataBuffer);
  const { rpIdHash, flags, counter } = parsedAuthData;

  // Make sure the response's RP ID is ours
  const expectedRPIDHash = toHash(Buffer.from(expectedRPID, 'ascii'));
  if (!rpIdHash.equals(expectedRPIDHash)) {
    throw new Error(`Unexpected RP ID hash`);
  }

  // Enforce user verification if required
  if (fidoUserVerification) {
    if (fidoUserVerification === 'required') {
      // Require `flags.uv` be true (implies `flags.up` is true)
      if (!flags.uv) {
        throw new Error('User verification required, but user could not be verified');
      }
    } else if (fidoUserVerification === 'preferred' || fidoUserVerification === 'discouraged') {
      // Ignore `flags.uv`
    }
  } else {
    // WebAuthn only requires the user presence flag be true
    if (!flags.up) {
      throw new Error('User not present during assertion');
    }
  }

  const clientDataHash = toHash(base64url.toBuffer(response.clientDataJSON));
  const signatureBase = Buffer.concat([authDataBuffer, clientDataHash]);

  const publicKey = convertPublicKeyToPEM(authenticator.publicKey);
  const signature = base64url.toBuffer(response.signature);

  if ((counter > 0 || authenticator.counter > 0) && counter <= authenticator.counter) {
    // Error out when the counter in the DB is greater than or equal to the counter in the
    // dataStruct. It's related to how the authenticator maintains the number of times its been
    // used for this client. If this happens, then someone's somehow increased the counter
    // on the device without going through this site
    throw new Error(
      `Response counter value ${counter} was lower than expected ${authenticator.counter}`,
    );
  }

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
