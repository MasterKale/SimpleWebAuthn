import type {
  COSEAlgorithmIdentifier,
  CredentialDeviceType,
  RegistrationResponseJSON,
  Uint8Array_,
  WebAuthnCredential,
} from '../types/index.ts';
import {
  type AttestationFormat,
  type AttestationStatement,
  decodeAttestationObject,
} from '../helpers/decodeAttestationObject.ts';
import type { AuthenticationExtensionsAuthenticatorOutputs } from '../helpers/decodeAuthenticatorExtensions.ts';
import { decodeClientDataJSON } from '../helpers/decodeClientDataJSON.ts';
import { parseAuthenticatorData } from '../helpers/parseAuthenticatorData.ts';
import { toHash } from '../helpers/toHash.ts';
import { decodeCredentialPublicKey } from '../helpers/decodeCredentialPublicKey.ts';
import { COSEKEYS } from '../helpers/cose.ts';
import { convertAAGUIDToString } from '../helpers/convertAAGUIDToString.ts';
import { parseBackupFlags } from '../helpers/parseBackupFlags.ts';
import { matchExpectedRPID } from '../helpers/matchExpectedRPID.ts';
import { isoBase64URL } from '../helpers/iso/index.ts';
import { SettingsService } from '../services/settingsService.ts';

import { supportedCOSEAlgorithmIdentifiers } from './generateRegistrationOptions.ts';
import { verifyAttestationFIDOU2F } from './verifications/verifyAttestationFIDOU2F.ts';
import { verifyAttestationPacked } from './verifications/verifyAttestationPacked.ts';
import { verifyAttestationAndroidSafetyNet } from './verifications/verifyAttestationAndroidSafetyNet.ts';
import { verifyAttestationTPM } from './verifications/tpm/verifyAttestationTPM.ts';
import { verifyAttestationAndroidKey } from './verifications/verifyAttestationAndroidKey.ts';
import { verifyAttestationApple } from './verifications/verifyAttestationApple.ts';

/**
 * Configurable options when calling `verifyRegistrationResponse()`
 */
export type VerifyRegistrationResponseOpts = Parameters<typeof verifyRegistrationResponse>[0];

/**
 * Verify that the user has legitimately completed the registration process
 *
 * **Options:**
 *
 * @param response - Response returned by **@simplewebauthn/browser**'s `startAuthentication()`
 * @param expectedChallenge - The base64url-encoded `options.challenge` returned by `generateRegistrationOptions()`
 * @param expectedOrigin - Website URL (or array of URLs) that the registration should have occurred on
 * @param expectedRPID - RP ID (or array of IDs) that was specified in the registration options
 * @param expectedType **(Optional)** - The response type expected ('webauthn.create')
 * @param requireUserPresence **(Optional)** - Enforce user presence by the authenticator (or skip it during auto registration) Defaults to `true`
 * @param requireUserVerification **(Optional)** - Enforce user verification by the authenticator (via PIN, fingerprint, etc...) Defaults to `true`
 * @param supportedAlgorithmIDs **(Optional)** - Array of numeric COSE algorithm identifiers supported for attestation by this RP. See https://www.iana.org/assignments/cose/cose.xhtml#algorithms. Defaults to all supported algorithm IDs
 */
export async function verifyRegistrationResponse(
  options: {
    response: RegistrationResponseJSON;
    expectedChallenge: string | ((challenge: string) => boolean | Promise<boolean>);
    expectedOrigin: string | string[];
    expectedRPID?: string | string[];
    expectedType?: string | string[];
    requireUserPresence?: boolean;
    requireUserVerification?: boolean;
    supportedAlgorithmIDs?: COSEAlgorithmIdentifier[];
  },
): Promise<VerifiedRegistrationResponse> {
  const {
    response,
    expectedChallenge,
    expectedOrigin,
    expectedRPID,
    expectedType,
    requireUserPresence = true,
    requireUserVerification = true,
    supportedAlgorithmIDs = supportedCOSEAlgorithmIdentifiers,
  } = options;
  const { id, rawId, type: credentialType, response: attestationResponse } = response;

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
    throw new Error(
      `Unexpected credential type ${credentialType}, expected "public-key"`,
    );
  }

  const clientDataJSON = decodeClientDataJSON(
    attestationResponse.clientDataJSON,
  );

  const { type, origin, challenge, tokenBinding } = clientDataJSON;

  // Make sure we're handling an registration
  if (Array.isArray(expectedType)) {
    if (!expectedType.includes(type)) {
      const joinedExpectedType = expectedType.join(', ');
      throw new Error(
        `Unexpected registration response type "${type}", expected one of: ${joinedExpectedType}`,
      );
    }
  } else if (expectedType) {
    if (type !== expectedType) {
      throw new Error(
        `Unexpected registration response type "${type}", expected "${expectedType}"`,
      );
    }
  } else if (type !== 'webauthn.create') {
    throw new Error(`Unexpected registration response type: ${type}`);
  }

  // Ensure the device provided the challenge we gave it
  if (typeof expectedChallenge === 'function') {
    if (!(await expectedChallenge(challenge))) {
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
        `Unexpected registration response origin "${origin}", expected one of: ${
          expectedOrigin.join(
            ', ',
          )
        }`,
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

    if (
      ['present', 'supported', 'not-supported'].indexOf(tokenBinding.status) < 0
    ) {
      throw new Error(
        `Unexpected tokenBinding.status value of "${tokenBinding.status}"`,
      );
    }
  }

  const attestationObject = isoBase64URL.toBuffer(
    attestationResponse.attestationObject,
  );
  const decodedAttestationObject = decodeAttestationObject(attestationObject);
  const fmt = decodedAttestationObject.get('fmt');
  const authData = decodedAttestationObject.get('authData');
  const attStmt = decodedAttestationObject.get('attStmt');

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
  let matchedRPID: string | undefined;
  if (expectedRPID) {
    let expectedRPIDs: string[] = [];
    if (typeof expectedRPID === 'string') {
      expectedRPIDs = [expectedRPID];
    } else {
      expectedRPIDs = expectedRPID;
    }

    matchedRPID = await matchExpectedRPID(rpIdHash, expectedRPIDs);
  }

  // Make sure someone was physically present
  if (requireUserPresence && !flags.up) {
    throw new Error('User presence was required, but user was not present');
  }

  // Enforce user verification if specified
  if (requireUserVerification && !flags.uv) {
    throw new Error(
      'User verification was required, but user could not be verified',
    );
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
    throw new Error(
      `Unexpected public key alg "${alg}", expected one of "${supported}"`,
    );
  }

  const clientDataHash = await toHash(
    isoBase64URL.toBuffer(attestationResponse.clientDataJSON),
  );
  const rootCertificates = SettingsService.getRootCertificates({
    identifier: fmt,
  });

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
    verified = await verifyAttestationFIDOU2F(verifierOpts);
  } else if (fmt === 'packed') {
    verified = await verifyAttestationPacked(verifierOpts);
  } else if (fmt === 'android-safetynet') {
    verified = await verifyAttestationAndroidSafetyNet(verifierOpts);
  } else if (fmt === 'android-key') {
    verified = await verifyAttestationAndroidKey(verifierOpts);
  } else if (fmt === 'tpm') {
    verified = await verifyAttestationTPM(verifierOpts);
  } else if (fmt === 'apple') {
    verified = await verifyAttestationApple(verifierOpts);
  } else if (fmt === 'none') {
    if (attStmt.size > 0) {
      throw new Error('None attestation had unexpected attestation statement');
    }
    // This is the weaker of the attestations, so there's nothing else to really check
    verified = true;
  } else {
    throw new Error(`Unsupported Attestation Format: ${fmt}`);
  }

  if (!verified) {
    return { verified: false };
  }

  const { credentialDeviceType, credentialBackedUp } = parseBackupFlags(flags);

  return {
    verified: true,
    registrationInfo: {
      fmt,
      aaguid: convertAAGUIDToString(aaguid),
      credentialType,
      credential: {
        id: isoBase64URL.fromBuffer(credentialID),
        publicKey: credentialPublicKey,
        counter,
        transports: response.response.transports,
      },
      attestationObject,
      userVerified: flags.uv,
      credentialDeviceType,
      credentialBackedUp,
      origin: clientDataJSON.origin,
      rpID: matchedRPID,
      authenticatorExtensionResults: extensionsData,
    },
  };
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
 * @param registrationInfo.origin The origin of the website that the registration occurred on
 * @param registrationInfo?.rpID The RP ID that the registration occurred on, if one or more were
 * specified in the registration options
 * @param registrationInfo?.authenticatorExtensionResults The authenticator extensions returned
 * by the browser
 */
export type VerifiedRegistrationResponse = {
  verified: false;
  registrationInfo?: never;
} | {
  verified: true;
  registrationInfo: {
    fmt: AttestationFormat;
    aaguid: string;
    credential: WebAuthnCredential;
    credentialType: 'public-key';
    attestationObject: Uint8Array_;
    userVerified: boolean;
    credentialDeviceType: CredentialDeviceType;
    credentialBackedUp: boolean;
    origin: string;
    rpID?: string;
    authenticatorExtensionResults?: AuthenticationExtensionsAuthenticatorOutputs;
  };
};

/**
 * Values passed to all attestation format verifiers, from which they are free to use as they please
 */
export type AttestationFormatVerifierOpts = {
  aaguid: Uint8Array_;
  attStmt: AttestationStatement;
  authData: Uint8Array_;
  clientDataHash: Uint8Array_;
  credentialID: Uint8Array_;
  credentialPublicKey: Uint8Array_;
  rootCertificates: string[];
  rpIdHash: Uint8Array_;
  verifyTimestampMS?: boolean;
};
