import { AttestationCredentials } from '@webauthntine/typescript-types';

/**
 * Prepare credentials for user registration via navigator.credentials.create(...)
 *
 * @param serviceName Friendly user-visible website name
 * @param rpID Valid domain name (after `https://`)
 * @param challenge Random string the authenticator needs to sign and pass back
 * @param userID User's website-specific unique ID
 * @param username User's website-specific username
 * @param timeout How long (in ms) the user can take to complete attestation
 * @param attestationType Request a full ("direct") or anonymized ("indirect") attestation statement
 */
export default function generateAttestationCredentials(
  serviceName: string,
  rpID: string,
  challenge: string,
  userID: string,
  username: string,
  timeout: number = 60000,
  attestationType: 'direct' | 'indirect' = 'direct',
): AttestationCredentials {
  return {
    publicKey: {
      // Cryptographically random bytes to prevent replay attacks
      challenge: Uint8Array.from(challenge, c => c.charCodeAt(0)),
      // The organization registering and authenticating the user
      rp: {
        name: serviceName,
        id: rpID,
      },
      user: {
        id: Uint8Array.from(userID, c => c.charCodeAt(0)),
        name: username,
        displayName: username,
      },
      pubKeyCredParams: [{
        alg: -7,
        type: 'public-key',
      }],
      timeout,
      attestation: attestationType,
    },
  };
}
