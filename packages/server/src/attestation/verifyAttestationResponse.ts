import base64url from 'base64url';
import { AttestationCredentialJSON } from '@simplewebauthn/typescript-types';

import decodeAttestationObject, { ATTESTATION_FORMATS } from '../helpers/decodeAttestationObject';
import decodeClientDataJSON from '../helpers/decodeClientDataJSON';
import parseAuthenticatorData from '../helpers/parseAuthenticatorData';
import toHash from '../helpers/toHash';
import decodeCredentialPublicKey from '../helpers/decodeCredentialPublicKey';
import convertCOSEtoPKCS, { COSEKEYS } from '../helpers/convertCOSEtoPKCS';

import { supportedCOSEAlgorithmIdentifiers } from './generateAttestationOptions';
import verifyFIDOU2F from './verifications/verifyFIDOU2F';
import verifyPacked from './verifications/verifyPacked';
import verifyAndroidSafetynet from './verifications/verifyAndroidSafetyNet';
import verifyTPM from './verifications/tpm/verifyTPM';
import verifyAndroidKey from './verifications/verifyAndroidKey';

type Options = {
  credential: AttestationCredentialJSON;
  expectedChallenge: string;
  expectedOrigin: string;
  expectedRPID?: string;
  requireUserVerification?: boolean;
};

/**
 * Verify that the user has legitimately completed the registration process
 *
 * **Options:**
 *
 * @param credential Authenticator credential returned by browser's `startAttestation()`
 * @param expectedChallenge The random value provided to generateAttestationOptions for the
 * authenticator to sign
 * @param expectedOrigin Website URL that the attestation should have occurred on
 * @param expectedRPID RP ID that was specified in the attestation options
 * @param requireUserVerification (Optional) Enforce user verification by the authenticator
 * (via PIN, fingerprint, etc...)
 */
export default async function verifyAttestationResponse(
  options: Options,
): Promise<VerifiedAttestation> {
  const {
    credential,
    expectedChallenge,
    expectedOrigin,
    expectedRPID,
    requireUserVerification = false,
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

  // Make sure we're handling an attestation
  if (type !== 'webauthn.create') {
    throw new Error(`Unexpected attestation type: ${type}`);
  }

  // Ensure the device provided the challenge we gave it
  const encodedExpectedChallenge = base64url.encode(expectedChallenge);
  if (challenge !== encodedExpectedChallenge) {
    throw new Error(
      `Unexpected attestation challenge "${challenge}", expected "${encodedExpectedChallenge}"`,
    );
  }

  // Check that the origin is our site
  if (origin !== expectedOrigin) {
    throw new Error(`Unexpected attestation origin "${origin}", expected "${expectedOrigin}"`);
  }

  if (tokenBinding) {
    if (!(tokenBinding instanceof Object)) {
      throw new Error(`Unexpected value for TokenBinding "${tokenBinding}"`);
    }

    if (['present', 'supported', 'not-supported'].indexOf(tokenBinding.status) < 0) {
      throw new Error(`Unexpected tokenBinding.status value of "${tokenBinding.status}"`);
    }
  }

  const attestationObject = decodeAttestationObject(response.attestationObject);
  const { fmt, authData, attStmt } = attestationObject;

  const parsedAuthData = parseAuthenticatorData(authData);
  const { aaguid, rpIdHash, flags, credentialID, counter, credentialPublicKey } = parsedAuthData;

  // Make sure the response's RP ID is ours
  if (expectedRPID) {
    const expectedRPIDHash = toHash(Buffer.from(expectedRPID, 'ascii'));
    if (!rpIdHash.equals(expectedRPIDHash)) {
      throw new Error(`Unexpected RP ID hash`);
    }
  }

  // Make sure someone was physically present
  if (!flags.up) {
    throw new Error('User not present during assertion');
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
    throw new Error('No AAGUID was present in attestation');
  }

  const decodedPublicKey = decodeCredentialPublicKey(credentialPublicKey);
  const alg = decodedPublicKey.get(COSEKEYS.alg);

  if (typeof alg !== 'number') {
    throw new Error('Credential public key was missing numeric alg');
  }

  // Make sure the key algorithm is one we specified within the attestation options
  if (!supportedCOSEAlgorithmIdentifiers.includes(alg as number)) {
    const supported = supportedCOSEAlgorithmIdentifiers.join(', ');
    throw new Error(`Unexpected public key alg "${alg}", expected one of "${supported}"`);
  }

  const clientDataHash = toHash(base64url.toBuffer(response.clientDataJSON));

  /**
   * Verification can only be performed when attestation = 'direct'
   */
  let verified = false;
  if (fmt === ATTESTATION_FORMATS.FIDO_U2F) {
    verified = verifyFIDOU2F({
      attStmt,
      clientDataHash,
      credentialID,
      credentialPublicKey,
      rpIdHash,
      aaguid,
    });
  } else if (fmt === ATTESTATION_FORMATS.PACKED) {
    verified = await verifyPacked({
      attStmt,
      authData,
      clientDataHash,
      credentialPublicKey,
      aaguid,
    });
  } else if (fmt === ATTESTATION_FORMATS.ANDROID_SAFETYNET) {
    verified = await verifyAndroidSafetynet({
      attStmt,
      authData,
      clientDataHash,
      aaguid,
    });
  } else if (fmt === ATTESTATION_FORMATS.ANDROID_KEY) {
    verified = await verifyAndroidKey({
      attStmt,
      authData,
      clientDataHash,
      credentialPublicKey,
      aaguid,
    });
  } else if (fmt === ATTESTATION_FORMATS.TPM) {
    verified = verifyTPM({
      aaguid,
      attStmt,
      authData,
      credentialPublicKey,
      clientDataHash,
    });
  } else if (fmt === ATTESTATION_FORMATS.NONE) {
    if (Object.keys(attStmt).length > 0) {
      throw new Error('None attestation had unexpected attestation statement');
    }
    // This is the weaker of the attestations, so there's nothing else to really check
    verified = true;
  } else {
    throw new Error(`Unsupported Attestation Format: ${fmt}`);
  }

  const toReturn: VerifiedAttestation = {
    verified,
    userVerified: flags.uv,
  };

  if (toReturn.verified) {
    toReturn.userVerified = flags.uv;

    const publicKey = convertCOSEtoPKCS(credentialPublicKey);

    toReturn.authenticatorInfo = {
      fmt,
      counter,
      base64PublicKey: base64url.encode(publicKey),
      base64CredentialID: base64url.encode(credentialID),
    };
  }

  return toReturn;
}

/**
 * Result of attestation verification
 *
 * @param verified If the assertion response could be verified
 * @param userVerified Whether the user was uniquely identified during attestation
 * @param authenticatorInfo.fmt Type of attestation
 * @param authenticatorInfo.counter The number of times the authenticator reported it has been used.
 * Should be kept in a DB for later reference to help prevent replay attacks
 * @param authenticatorInfo.base64PublicKey Base64URL-encoded ArrayBuffer containing the
 * authenticator's public key. **Should be kept in a DB for later reference!**
 * @param authenticatorInfo.base64CredentialID Base64URL-encoded ArrayBuffer containing the
 * authenticator's credential ID for the public key above. **Should be kept in a DB for later
 * reference!**
 */
export type VerifiedAttestation = {
  verified: boolean;
  userVerified: boolean;
  authenticatorInfo?: {
    fmt: ATTESTATION_FORMATS;
    counter: number;
    base64PublicKey: string;
    base64CredentialID: string;
  };
};
