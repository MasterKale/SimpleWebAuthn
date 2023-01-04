import type {
  AttestationConveyancePreference,
  AuthenticationExtensionsClientInputs,
  AuthenticatorSelectionCriteria,
  COSEAlgorithmIdentifier,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialDescriptorFuture,
  PublicKeyCredentialParameters,
} from '@simplewebauthn/typescript-types';

import { generateChallenge } from '../helpers/generateChallenge';
import { isoBase64URL, isoUint8Array } from '../helpers/iso';

export type GenerateRegistrationOptionsOpts = {
  rpName: string;
  rpID: string;
  userID: string;
  userName: string;
  challenge?: string | Uint8Array;
  userDisplayName?: string;
  timeout?: number;
  attestationType?: AttestationConveyancePreference;
  excludeCredentials?: PublicKeyCredentialDescriptorFuture[];
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  extensions?: AuthenticationExtensionsClientInputs;
  supportedAlgorithmIDs?: COSEAlgorithmIdentifier[];
};

/**
 * Supported crypto algo identifiers
 * See https://w3c.github.io/webauthn/#sctn-alg-identifier
 * and https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 */
export const supportedCOSEAlgorithmIdentifiers: COSEAlgorithmIdentifier[] = [
  // EdDSA (In first position to encourage authenticators to use this over ES256)
  -8,
  // ECDSA w/ SHA-256
  -7,
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
  residentKey: 'preferred',
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
 */
export function generateRegistrationOptions(
  options: GenerateRegistrationOptionsOpts,
): PublicKeyCredentialCreationOptionsJSON {
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
  } = options;

  /**
   * Prepare pubKeyCredParams from the array of algorithm ID's
   */
  const pubKeyCredParams: PublicKeyCredentialParameters[] = supportedAlgorithmIDs.map(id => ({
    alg: id,
    type: 'public-key',
  }));

  /**
   * Capture some of the nuances of how `residentKey` and `requireResidentKey` how either is set
   * depending on when either is defined in the options
   */
  if (authenticatorSelection.residentKey === undefined) {
    /**
     * `residentKey`: "If no value is given then the effective value is `required` if
     * requireResidentKey is true or `discouraged` if it is false or absent."
     *
     * See https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-residentkey
     */
    if (authenticatorSelection.requireResidentKey) {
      authenticatorSelection.residentKey = 'required';
    } else {
      /**
       * FIDO Conformance v1.7.2 fails the first test if we do this, even though this is
       * technically compatible with the WebAuthn L2 spec...
       */
      // authenticatorSelection.residentKey = 'discouraged';
    }
  } else {
    /**
     * `requireResidentKey`: "Relying Parties SHOULD set it to true if, and only if, residentKey is
     * set to "required""
     *
     * Spec says this property defaults to `false` so we should still be okay to assign `false` too
     *
     * See https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-requireresidentkey
     */
    authenticatorSelection.requireResidentKey = authenticatorSelection.residentKey === 'required';
  }

  /**
   * Preserve ability to specify `string` values for challenges
   */
  let _challenge = challenge;
  if (typeof _challenge === 'string') {
    _challenge = isoUint8Array.fromASCIIString(_challenge);
  }

  return {
    challenge: isoBase64URL.fromBuffer(_challenge),
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
    excludeCredentials: excludeCredentials.map(cred => ({
      ...cred,
      id: isoBase64URL.fromBuffer(cred.id as Uint8Array),
    })),
    authenticatorSelection,
    extensions: {
      ...extensions,
      credProps: true,
    },
  };
}
