import base64url from 'base64url';
import {
  RegistrationCredentialJSON,
  COSEAlgorithmIdentifier,
  CredentialDeviceType,
} from '@simplewebauthn/typescript-types';

import {
  AttestationFormat,
  AttestationStatement,
  decodeAttestationObject,
} from '../helpers/decodeAttestationObject';
import { AuthenticationExtensionsAuthenticatorOutputs } from '../helpers/decodeAuthenticatorExtensions';
import { decodeClientDataJSON } from '../helpers/decodeClientDataJSON';
import { parseAuthenticatorData } from '../helpers/parseAuthenticatorData';
import { toHash } from '../helpers/toHash';
import { decodeCredentialPublicKey } from '../helpers/decodeCredentialPublicKey';
import { COSEKEYS } from '../helpers/convertCOSEtoPKCS';
import { convertAAGUIDToString } from '../helpers/convertAAGUIDToString';
import { parseBackupFlags } from '../helpers/parseBackupFlags';
import settingsService from '../services/settingsService';

import { supportedCOSEAlgorithmIdentifiers } from './generateRegistrationOptions';
import verifyFIDOU2F from './verifications/verifyFIDOU2F';
import verifyPacked from './verifications/verifyPacked';
import verifyAndroidSafetynet from './verifications/verifyAndroidSafetyNet';
import verifyTPM from './verifications/tpm/verifyTPM';
import verifyAndroidKey from './verifications/verifyAndroidKey';
import verifyApple from './verifications/verifyApple';

export type VerifyRegistrationResponseOpts = {
  credential: RegistrationCredentialJSON;
  expectedChallenge: string | ((challenge: string) => boolean);
  expectedOrigin: string | string[];
  expectedRPID?: string | string[];
  requireUserVerification?: boolean;
  supportedAlgorithmIDs?: COSEAlgorithmIdentifier[];
};

/**
 * Verify that the user has legitimately completed the registration process
 *
 * **Options:**
 *
 * @param credential Authenticator credential returned by browser's `startAuthentication()`
 * @param expectedChallenge The base64url-encoded `options.challenge` returned by
 * `generateRegistrationOptions()`
 * @param expectedOrigin Website URL (or array of URLs) that the registration should have occurred on
 * @param expectedRPID RP ID (or array of IDs) that was specified in the registration options
 * @param requireUserVerification (Optional) Enforce user verification by the authenticator
 * (via PIN, fingerprint, etc...)
 * @param supportedAlgorithmIDs Array of numeric COSE algorithm identifiers supported for
 * attestation by this RP. See https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 */
export async function verifyRegistrationResponse(
  options: VerifyRegistrationResponseOpts,
): Promise<VerifiedRegistrationResponse> {
  const {
    credential,
    expectedChallenge,
    expectedOrigin,
    expectedRPID,
    requireUserVerification = false,
    supportedAlgorithmIDs = supportedCOSEAlgorithmIdentifiers,
  } = options;
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

  const clientDataJSON = decodeClientDataJSON(response.clientDataJSON);

  const { type, origin, challenge, tokenBinding } = clientDataJSON;

  // Make sure we're handling an registration
  if (type !== 'webauthn.create') {
    throw new Error(`Unexpected registration response type: ${type}`);
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
      `Unexpected registration response challenge "${challenge}", expected "${expectedChallenge}"`,
    );
  }

  // Check that the origin is our site
  if (Array.isArray(expectedOrigin)) {
    if (!expectedOrigin.includes(origin)) {
      throw new Error(
        `Unexpected registration response origin "${origin}", expected one of: ${expectedOrigin.join(
          ', ',
        )}`,
      );
    }
  } else {
    if (origin !== expectedOrigin) {
      throw new Error(
        `Unexpected registration response origin "${origin}", expected "${expectedOrigin}"`,
      );
    }
  }

  if (tokenBinding) {
    if (typeof tokenBinding !== 'object') {
      throw new Error(`Unexpected value for TokenBinding "${tokenBinding}"`);
    }

    if (['present', 'supported', 'not-supported'].indexOf(tokenBinding.status) < 0) {
      throw new Error(`Unexpected tokenBinding.status value of "${tokenBinding.status}"`);
    }
  }

  const attestationObject = base64url.toBuffer(response.attestationObject);
  const decodedAttestationObject = decodeAttestationObject(attestationObject);
  const { fmt, authData, attStmt } = decodedAttestationObject;

  const parsedAuthData = parseAuthenticatorData(authData);
  const {
    aaguid,
    rpIdHash,
    flags,
    credentialID,
    counter,
    credentialPublicKey,
    extensionsData,
  } = parsedAuthData;

  // Make sure the response's RP ID is ours
  if (expectedRPID) {
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
  }

  // Make sure someone was physically present
  if (!flags.up) {
    throw new Error('User not present during registration');
  }

  // Enforce user verification if specified
  if (requireUserVerification && !flags.uv) {
    throw new Error('User verification required, but user could not be verified');
  }

  if (!credentialID) {
    throw new Error('No credential ID was provided by authenticator');
  }

  if (!credentialPublicKey) {
    throw new Error('No public key was provided by authenticator');
  }

  if (!aaguid) {
    throw new Error('No AAGUID was present during registration');
  }

  const decodedPublicKey = decodeCredentialPublicKey(credentialPublicKey);
  const alg = decodedPublicKey.get(COSEKEYS.alg);

  if (typeof alg !== 'number') {
    throw new Error('Credential public key was missing numeric alg');
  }

  // Make sure the key algorithm is one we specified within the registration options
  if (!supportedAlgorithmIDs.includes(alg as number)) {
    const supported = supportedAlgorithmIDs.join(', ');
    throw new Error(`Unexpected public key alg "${alg}", expected one of "${supported}"`);
  }

  const clientDataHash = toHash(base64url.toBuffer(response.clientDataJSON));
  const rootCertificates = settingsService.getRootCertificates({ identifier: fmt });

  // Prepare arguments to pass to the relevant verification method
  const verifierOpts: AttestationFormatVerifierOpts = {
    aaguid,
    attStmt,
    authData,
    clientDataHash,
    credentialID,
    credentialPublicKey,
    rootCertificates,
    rpIdHash,
  };

  /**
   * Verification can only be performed when attestation = 'direct'
   */
  let verified = false;
  if (fmt === 'fido-u2f') {
    verified = await verifyFIDOU2F(verifierOpts);
  } else if (fmt === 'packed') {
    verified = await verifyPacked(verifierOpts);
  } else if (fmt === 'android-safetynet') {
    verified = await verifyAndroidSafetynet(verifierOpts);
  } else if (fmt === 'android-key') {
    verified = await verifyAndroidKey(verifierOpts);
  } else if (fmt === 'tpm') {
    verified = await verifyTPM(verifierOpts);
  } else if (fmt === 'apple') {
    verified = await verifyApple(verifierOpts);
  } else if (fmt === 'none') {
    if (Object.keys(attStmt).length > 0) {
      throw new Error('None attestation had unexpected attestation statement');
    }
    // This is the weaker of the attestations, so there's nothing else to really check
    verified = true;
  } else {
    throw new Error(`Unsupported Attestation Format: ${fmt}`);
  }

  const toReturn: VerifiedRegistrationResponse = {
    verified,
  };

  if (toReturn.verified) {
    const { credentialDeviceType, credentialBackedUp } = parseBackupFlags(flags);

    toReturn.registrationInfo = {
      fmt,
      counter,
      aaguid: convertAAGUIDToString(aaguid),
      credentialID,
      credentialPublicKey,
      credentialType,
      attestationObject,
      userVerified: flags.uv,
      credentialDeviceType,
      credentialBackedUp,
      authenticatorExtensionResults: extensionsData,
    };
  }

  return toReturn;
}

/**
 * Result of registration verification
 *
 * @param verified If the assertion response could be verified
 * @param registrationInfo.fmt Type of attestation
 * @param registrationInfo.counter The number of times the authenticator reported it has been used.
 * **Should be kept in a DB for later reference to help prevent replay attacks!**
 * @param registrationInfo.aaguid Authenticator's Attestation GUID indicating the type of the
 * authenticator
 * @param registrationInfo.credentialPublicKey The credential's public key
 * @param registrationInfo.credentialID The credential's credential ID for the public key above
 * @param registrationInfo.credentialType The type of the credential returned by the browser
 * @param registrationInfo.userVerified Whether the user was uniquely identified during attestation
 * @param registrationInfo.attestationObject The raw `response.attestationObject` Buffer returned by
 * the authenticator
 * @param registrationInfo.credentialDeviceType Whether this is a single-device or multi-device
 * credential. **Should be kept in a DB for later reference!**
 * @param registrationInfo.credentialBackedUp Whether or not the multi-device credential has been
 * backed up. Always `false` for single-device credentials. **Should be kept in a DB for later
 * reference!**
 * @param registrationInfo?.authenticatorExtensionResults The authenticator extensions returned
 * by the browser
 */
export type VerifiedRegistrationResponse = {
  verified: boolean;
  registrationInfo?: {
    fmt: AttestationFormat;
    counter: number;
    aaguid: string;
    credentialID: Buffer;
    credentialPublicKey: Buffer;
    credentialType: "public-key";
    attestationObject: Buffer;
    userVerified: boolean;
    credentialDeviceType: CredentialDeviceType;
    credentialBackedUp: boolean;
    authenticatorExtensionResults?: AuthenticationExtensionsAuthenticatorOutputs;
  };
};

/**
 * Values passed to all attestation format verifiers, from which they are free to use as they please
 */
export type AttestationFormatVerifierOpts = {
  aaguid: Buffer;
  attStmt: AttestationStatement;
  authData: Buffer;
  clientDataHash: Buffer;
  credentialID: Buffer;
  credentialPublicKey: Buffer;
  rootCertificates: string[];
  rpIdHash: Buffer;
  verifyTimestampMS?: boolean;
};
