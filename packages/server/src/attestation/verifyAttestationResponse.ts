import decodeAttestationObject from '../helpers/decodeAttestationObject';
import decodeClientDataJSON from '../helpers/decodeClientDataJSON';
import {
  ATTESTATION_FORMATS,
  AuthenticatorAttestationResponseJSON,
  VerifiedAttestation,
} from '@simplewebauthn/typescript-types';

import verifyFIDOU2F from './verifications/verifyFIDOU2F';
import verifyPacked from './verifications/verifyPacked';
import verifyNone from './verifications/verifyNone';
import verifyAndroidSafetynet from './verifications/verifyAndroidSafetyNet';

/**
 * Verify that the user has legitimately completed the registration process
 *
 * @param response Authenticator attestation response with base64-encoded values
 * @param expectedChallenge The random value provided to generateAttestationOptions for the
 * authenticator to sign
 * @param expectedOrigin Expected URL of website attestation should have occurred on
 */
export default function verifyAttestationResponse(
  response: AuthenticatorAttestationResponseJSON,
  expectedChallenge: string,
  expectedOrigin: string,
): VerifiedAttestation {
  const { base64AttestationObject, base64ClientDataJSON } = response;
  const attestationObject = decodeAttestationObject(base64AttestationObject);
  const clientDataJSON = decodeClientDataJSON(base64ClientDataJSON);

  const { type, origin, challenge } = clientDataJSON;

  if (challenge !== expectedChallenge) {
    throw new Error(
      `Unexpected attestation challenge "${challenge}", expected "${expectedChallenge}"`,
    );
  }

  // Check that the origin is our site
  if (origin !== expectedOrigin) {
    throw new Error(`Unexpected attestation origin "${origin}", expected "${expectedOrigin}"`);
  }

  // Make sure we're handling an attestation
  if (type !== 'webauthn.create') {
    throw new Error(`Unexpected attestation type: ${type}`);
  }

  const { fmt } = attestationObject;

  /**
   * Verification can only be performed when attestation = 'direct'
   */
  if (fmt === ATTESTATION_FORMATS.FIDO_U2F) {
    return verifyFIDOU2F(attestationObject, base64ClientDataJSON);
  }

  if (fmt === ATTESTATION_FORMATS.PACKED) {
    return verifyPacked(attestationObject, base64ClientDataJSON);
  }

  if (fmt === ATTESTATION_FORMATS.ANDROID_SAFETYNET) {
    return verifyAndroidSafetynet(attestationObject, base64ClientDataJSON);
  }

  if (fmt === ATTESTATION_FORMATS.NONE) {
    return verifyNone(attestationObject);
  }

  throw new Error(`Unsupported Attestation Format: ${fmt}`);
}
