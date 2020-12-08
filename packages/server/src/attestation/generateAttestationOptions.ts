import type {
  AuthenticatorSelectionCriteria,
  COSEAlgorithmIdentifier,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialParameters,
} from '@simplewebauthn/typescript-types';
import Adapter from 'adapters/Adapter';
import base64url from 'base64url';
import reducePromise from '../helpers/reducePromise';
import generateChallenge from '../helpers/generateChallenge';
import { GenerateAttestationOptions } from './options';

/**
 * Supported crypto algo identifiers
 * See https://w3c.github.io/webauthn/#sctn-alg-identifier
 * and https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 */
export const supportedCOSEAlgorithmIdentifiers: COSEAlgorithmIdentifier[] = [
  // ECDSA w/ SHA-256
  -7,
  // EdDSA
  -8,
  // ECDSA w/ SHA-512
  -36,
  // RSASSA-PSS w/ SHA-256
  -37,
  // RSASSA-PSS w/ SHA-384
  -38,
  // RSASSA-PSS w/ SHA-512
  -39,
  // RSASSA-PKCS1-v1_5 w/ SHA-256
  -257,
  // RSASSA-PKCS1-v1_5 w/ SHA-384
  -258,
  // RSASSA-PKCS1-v1_5 w/ SHA-512
  -259,
  // RSASSA-PKCS1-v1_5 w/ SHA-1 (Deprecated; here for legacy support)
  -65535,
];

/**
 * Set up some default authenticator selection options as per the latest spec:
 * https://www.w3.org/TR/webauthn-2/#dictdef-authenticatorselectioncriteria
 *
 * Helps with some older platforms (e.g. Android 7.0 Nougat) that may not be aware of these
 * defaults.
 */
const defaultAuthenticatorSelection: AuthenticatorSelectionCriteria = {
  requireResidentKey: false,
  userVerification: 'preferred',
};

/**
 * Filter out known bad/deprecated/etc... algorithm ID's so they're not used for new attestations.
 * See https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 */
const defaultSupportedAlgorithmIDs = supportedCOSEAlgorithmIdentifiers.filter(id => id !== -65535);

/**
 * Prepare a value to pass into navigator.credentials.create(...) for authenticator "registration"
 *
 * **Options:**
 *
 * @param rpName User-visible, "friendly" website/service name
 * @param rpID Valid domain name (after `https://`)
 * @param userID User's website-specific unique ID
 * @param userName User's website-specific username (email, etc...)
 * @param challenge Random value the authenticator needs to sign and pass back
 * @param userDisplayName User's actual name
 * @param timeout How long (in ms) the user can take to complete attestation
 * @param attestationType Specific attestation statement
 * @param excludeCredentials Authenticators registered by the user so the user can't register the
 * same credential multiple times
 * @param authenticatorSelection Advanced criteria for restricting the types of authenticators that
 * may be used
 * @param extensions Additional plugins the authenticator or browser should use during attestation
 * @param supportedAlgorithmIDs Array of numeric COSE algorithm identifiers supported for
 * attestation by this RP. See https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 *  * @param serverSecret A global random string with at least 64 chars (from env vars for example)
 * to avoid storing the challenge into your DB, and enable stateless challenge validation
 */
export default async function generateAttestationOptions(
  options: GenerateAttestationOptions,
): Promise<PublicKeyCredentialCreationOptionsJSON> {
  const {
    rpName,
    rpID,
    userID,
    userName,
    challenge = generateChallenge(),
    userDisplayName = userName,
    timeout = 60000,
    attestationType = 'none',
    excludeCredentials = [],
    authenticatorSelection = defaultAuthenticatorSelection,
    extensions,
    supportedAlgorithmIDs = defaultSupportedAlgorithmIDs,
    adapters,
  } = options;

  /**
   * Prepare pubKeyCredParams from the array of algorithm ID's
   */
  const pubKeyCredParams: PublicKeyCredentialParameters[] = supportedAlgorithmIDs.map(id => ({
    alg: id,
    type: 'public-key',
  }));

  const base64Challenge = base64url.encode(challenge);
  const response = {
    challenge: base64Challenge,
    rp: {
      name: rpName,
      id: rpID,
    },
    user: {
      id: userID,
      name: userName,
      displayName: userDisplayName,
    },
    pubKeyCredParams,
    timeout,
    attestation: attestationType,
    excludeCredentials,
    authenticatorSelection,
    extensions,
  };

  if (!adapters) return response;

  return reducePromise<Adapter, PublicKeyCredentialCreationOptionsJSON>(
    adapters,
    (acc, adapter) => adapter.attest(acc),
    response,
  );
}
