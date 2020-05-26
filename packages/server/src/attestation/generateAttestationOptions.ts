import { PublicKeyCredentialCreationOptionsJSON } from '@simplewebauthn/typescript-types';

/**
 * Prepare a value to pass into navigator.credentials.create(...) for authenticator "registration"
 *
 * @param serviceName Friendly user-visible website name
 * @param rpID Valid domain name (after `https://`)
 * @param challenge Random string the authenticator needs to sign and pass back
 * @param userID User's website-specific unique ID
 * @param username User's website-specific username
 * @param timeout How long (in ms) the user can take to complete attestation
 * @param attestationType Request a full ("direct") or anonymized ("indirect") attestation statement
 * @param excludedBase64CredentialIDs Array of base64-encoded authenticator IDs registered by the
 * user so the user can't register the same credential multiple times
 * @param suggestedTransports Suggested types of authenticators for attestation
 */
export default function generateAttestationOptions(
  serviceName: string,
  rpID: string,
  challenge: string,
  userID: string,
  username: string,
  timeout = 60000,
  attestationType: 'direct' | 'indirect' = 'direct',
  excludedBase64CredentialIDs: string[] = [],
  suggestedTransports: AuthenticatorTransport[] = ['usb', 'ble', 'nfc', 'internal'],
): PublicKeyCredentialCreationOptionsJSON {
  return {
    publicKey: {
      // Cryptographically random bytes to prevent replay attacks
      challenge,
      // The organization registering and authenticating the user
      rp: {
        name: serviceName,
        id: rpID,
      },
      user: {
        id: userID,
        name: username,
        displayName: username,
      },
      pubKeyCredParams: [
        {
          alg: -7,
          type: 'public-key',
        },
      ],
      timeout,
      attestation: attestationType,
      excludeCredentials: excludedBase64CredentialIDs.map((id) => ({
        id,
        type: 'public-key',
        transports: suggestedTransports,
      })),
    },
  };
}
