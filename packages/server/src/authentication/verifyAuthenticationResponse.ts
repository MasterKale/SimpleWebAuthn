import base64url from 'base64url';
import {
  AuthenticationCredentialJSON,
  AuthenticatorDevice,
  CredentialDeviceType,
  UserVerificationRequirement,
} from '@simplewebauthn/typescript-types';

import { decodeClientDataJSON } from '../helpers/decodeClientDataJSON';
import { toHash } from '../helpers/toHash';
import { verifySignature } from '../helpers/verifySignature';
import { parseAuthenticatorData } from '../helpers/parseAuthenticatorData';
import { isBase64URLString } from '../helpers/isBase64URLString';
import { parseBackupFlags } from '../helpers/parseBackupFlags';
import { DevicePublicKeyAuthenticatorOutput } from '../helpers/decodeAuthenticatorExtensions';
import { verifyDevicePublicKeySignature, VerifyDevicePublicKeySignatureOpts } from '../extensions/devicePublicKey/verifyDevicePublicKeySignature';
import { isRecognizedDevice } from '../extensions/devicePublicKey/isRecognizedDevice';

export type VerifyAuthenticationResponseOpts = {
  credential: AuthenticationCredentialJSON;
  expectedChallenge: string | ((challenge: string) => boolean);
  expectedOrigin: string | string[];
  expectedRPID: string | string[];
  authenticator: AuthenticatorDevice;
  requireUserVerification?: boolean;
  advancedFIDOConfig?: {
    userVerification?: UserVerificationRequirement;
  };
  userDevicePublicKeys?: DevicePublicKeyAuthenticatorOutput[];
};

/**
 * Verify that the user has legitimately completed the login process
 *
 * **Options:**
 *
 * @param credential Authenticator credential returned by browser's `startAssertion()`
 * @param expectedChallenge The base64url-encoded `options.challenge` returned by
 * `generateAssertionOptions()`
 * @param expectedOrigin Website URL (or array of URLs) that the registration should have occurred on
 * @param expectedRPID RP ID (or array of IDs) that was specified in the registration options
 * @param authenticator An internal {@link AuthenticatorDevice} matching the credential's ID
 * @param requireUserVerification (Optional) Enforce user verification by the authenticator
 * (via PIN, fingerprint, etc...)
 * @param advancedFIDOConfig (Optional) Options for satisfying more stringent FIDO RP feature
 * requirements
 * @param advancedFIDOConfig.userVerification (Optional) Enable alternative rules for evaluating the
 * User Presence and User Verified flags in authenticator data: UV (and UP) flags are optional
 * unless this value is `"required"`
 */
export async function verifyAuthenticationResponse(
  options: VerifyAuthenticationResponseOpts,
): Promise<VerifiedAuthenticationResponse> {
  const {
    credential,
    expectedChallenge,
    expectedOrigin,
    expectedRPID,
    authenticator,
    requireUserVerification,
    advancedFIDOConfig,
    userDevicePublicKeys,
  } = options;
  const { id, rawId, type: credentialType, response, clientExtensionResults } = credential;

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

  // Make sure we're handling an authentication
  if (type !== 'webauthn.get') {
    throw new Error(`Unexpected authentication response type: ${type}`);
  }

  // Ensure the device provided the challenge we gave it
  if (typeof expectedChallenge === 'function') {
    if (!expectedChallenge(challenge)) {
      throw new Error(
        `Custom challenge verifier returned false for registration response challenge "${challenge}"`,
      );
    }
  } else if (challenge !== expectedChallenge) {
    throw new Error(
      `Unexpected authentication response challenge "${challenge}", expected "${expectedChallenge}"`,
    );
  }

  // Check that the origin is our site
  if (Array.isArray(expectedOrigin)) {
    if (!expectedOrigin.includes(origin)) {
      const joinedExpectedOrigin = expectedOrigin.join(', ');
      throw new Error(
        `Unexpected authentication response origin "${origin}", expected one of: ${joinedExpectedOrigin}`,
      );
    }
  } else {
    if (origin !== expectedOrigin) {
      throw new Error(
        `Unexpected authentication response origin "${origin}", expected "${expectedOrigin}"`,
      );
    }
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
  const { rpIdHash, flags, counter, extensionsData } = parsedAuthData;

  // Make sure the response's RP ID is ours
  if (typeof expectedRPID === 'string') {
    const expectedRPIDHash = toHash(Buffer.from(expectedRPID, 'ascii'));
    if (!rpIdHash.equals(expectedRPIDHash)) {
      throw new Error(`Unexpected RP ID hash`);
    }
  } else {
    // Go through each expected RP ID and try to find one that matches
    const foundMatch = expectedRPID.some(expected => {
      const expectedRPIDHash = toHash(Buffer.from(expected, 'ascii'));
      return rpIdHash.equals(expectedRPIDHash);
    });

    if (!foundMatch) {
      throw new Error(`Unexpected RP ID hash`);
    }
  }

  if (advancedFIDOConfig !== undefined) {
    const { userVerification: fidoUserVerification } = advancedFIDOConfig;

    /**
     * Use FIDO Conformance-defined rules for verifying UP and UV flags
     */
    if (fidoUserVerification === 'required') {
      // Require `flags.uv` be true (implies `flags.up` is true)
      if (!flags.uv) {
        throw new Error('User verification required, but user could not be verified');
      }
    } else if (fidoUserVerification === 'preferred' || fidoUserVerification === 'discouraged') {
      // Ignore `flags.uv`
    }
  } else {
    /**
     * Use WebAuthn spec-defined rules for verifying UP and UV flags
     */
    // WebAuthn only requires the user presence flag be true
    if (!flags.up) {
      throw new Error('User not present during authentication');
    }

    // Enforce user verification if required
    if (requireUserVerification && !flags.uv) {
      throw new Error('User verification required, but user could not be verified');
    }
  }

  const extensionOutputs: ExtensionOutputs = {};

  if (flags.ed) {
    if (!extensionsData && !clientExtensionResults) {
      throw new Error('Authenticator data indicated extension data was present,'+
        ' but no client or authenticator extension data were found');
    }

    // TODO: Find a good way to check that returned extension outputs match what
    // was requested in extension inputs. See 7.1 step 18 in the spec.

    // DevicePublicKey sample currently provides the data through authenticator
    // extension results.
    if (extensionsData?.devicePubKey) {
      const { devicePubKey } = extensionsData;
      const { sig: dpkSig } = devicePubKey;

      if (!dpkSig) {
        throw new Error('DevicePublicKey was missing signature.');
      }
      const dpkOptions: VerifyDevicePublicKeySignatureOpts = {
        credential,
        devicePubKey,
        signature: dpkSig,
      };
      const result = await verifyDevicePublicKeySignature(dpkOptions);
      if (!result) {
        throw new Error('DevicePublicKey signature could not be verified');
      }
      const devicePubKeyToStore = await isRecognizedDevice(devicePubKey, userDevicePublicKeys);
      extensionOutputs.devicePubKeyToStore = devicePubKeyToStore;
    }
  }

  const clientDataHash = toHash(base64url.toBuffer(response.clientDataJSON));
  const signatureBase = Buffer.concat([authDataBuffer, clientDataHash]);

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

  const { credentialDeviceType, credentialBackedUp } = parseBackupFlags(flags);

  const toReturn: VerifiedAuthenticationResponse = {
    verified: await verifySignature({
      signature,
      signatureBase,
      credentialPublicKey: authenticator.credentialPublicKey,
    }),
    authenticationInfo: {
      newCounter: counter,
      credentialID: authenticator.credentialID,
      userVerified: flags.uv,
      credentialDeviceType,
      credentialBackedUp,
      extensionOutputs,
    },
  };

  return toReturn;
}

/**
 * Result of authentication verification
 *
 * @param verified If the authentication response could be verified
 * @param authenticationInfo.credentialID The ID of the authenticator used during authentication.
 * Should be used to identify which DB authenticator entry needs its `counter` updated to the value
 * below
 * @param authenticationInfo.newCounter The number of times the authenticator identified above
 * reported it has been used. **Should be kept in a DB for later reference to help prevent replay
 * attacks!**
 * @param authenticationInfo.credentialDeviceType Whether this is a single-device or multi-device
 * credential. **Should be kept in a DB for later reference!**
 * @param authenticationInfo.credentialBackedUp Whether or not the multi-device credential has been
 * backed up. Always `false` for single-device credentials. **Should be kept in a DB for later
 * reference!**
 * @param authenticationInfo?.authenticatorExtensionResults The authenticator extensions returned
 * by the browser
 */
export type VerifiedAuthenticationResponse = {
  verified: boolean;
  authenticationInfo: {
    credentialID: Buffer;
    newCounter: number;
    userVerified: boolean;
    credentialDeviceType: CredentialDeviceType;
    credentialBackedUp: boolean;
    extensionOutputs: ExtensionOutputs;
  };
};

export type ExtensionOutputs = {
  devicePubKeyToStore?: DevicePublicKeyAuthenticatorOutput;
}
