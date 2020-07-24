import type {
  PublicKeyCredentialCreationOptionsJSON,
  Base64URLString,
} from '@simplewebauthn/typescript-types';

type Options = {
  serviceName: string;
  rpID: string;
  challenge: string;
  userID: string;
  userName: string;
  userDisplayName?: string;
  timeout?: number;
  attestationType?: AttestationConveyancePreference;
  excludedCredentialIDs?: Base64URLString[];
  suggestedTransports?: AuthenticatorTransport[];
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  extensions?: AuthenticationExtensionsClientInputs;
};

// Supported crypto algo identifiers
// See https://w3c.github.io/webauthn/#sctn-alg-identifier
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
];

/**
 * Prepare a value to pass into navigator.credentials.create(...) for authenticator "registration"
 *
 * **Options:**
 *
 * @param serviceName Friendly user-visible website name
 * @param rpID Valid domain name (after `https://`)
 * @param challenge Random string the authenticator needs to sign and pass back
 * @param userID User's website-specific unique ID
 * @param userName User's website-specific username (email, etc...)
 * @param userDisplayName User's actual name
 * @param timeout How long (in ms) the user can take to complete attestation
 * @param attestationType Specific attestation statement
 * @param excludedCredentialIDs Array of base64url-encoded authenticator IDs registered by the
 * user so the user can't register the same credential multiple times
 * @param suggestedTransports Suggested types of authenticators for attestation
 * @param authenticatorSelection Advanced criteria for restricting the types of authenticators that
 * may be used
 * @param extensions Additional plugins the authenticator or browser should use during attestation
 */
export default function generateAttestationOptions(
  options: Options,
): PublicKeyCredentialCreationOptionsJSON {
  const {
    serviceName,
    rpID,
    challenge,
    userID,
    userName,
    userDisplayName = userName,
    timeout = 60000,
    attestationType = 'none',
    excludedCredentialIDs = [],
    suggestedTransports = ['usb', 'ble', 'nfc', 'internal'],
    authenticatorSelection,
    extensions,
  } = options;

  return {
    challenge,
    rp: {
      name: serviceName,
      id: rpID,
    },
    user: {
      id: userID,
      name: userName,
      displayName: userDisplayName,
    },
    pubKeyCredParams: supportedCOSEAlgorithmIdentifiers.map(id => ({
      alg: id,
      type: 'public-key',
    })),
    timeout,
    attestation: attestationType,
    excludeCredentials: excludedCredentialIDs.map(id => ({
      id,
      type: 'public-key',
      transports: suggestedTransports,
    })),
    authenticatorSelection,
    extensions,
  };
}
