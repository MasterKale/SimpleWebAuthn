import type {
  PublicKeyCredentialCreationOptionsJSON,
  AuthenticatorAttestationResponseJSON,
} from '@webauthntine/typescript-types';
import toUint8Array from '../helpers/toUint8Array';
import toBase64String from '../helpers/toBase64String';
import supportsWebauthn from '../helpers/supportsWebauthn';
import toPublicKeyCredentialDescriptor from '../helpers/toPublicKeyCredentialDescriptor';

/**
 * Begin authenticator "registration" via WebAuthn attestation
 *
 * @param creationOptionsJSON Output from @webauthntine/server's generateAttestationOptions(...)
 */
export default async function startAttestation(
  creationOptionsJSON: PublicKeyCredentialCreationOptionsJSON
): Promise<AuthenticatorAttestationResponseJSON> {
  if (!supportsWebauthn()) {
    throw new Error('WebAuthn is not supported in this browser');
  }

  // We need to convert some values to Uint8Arrays before passing the credentials to the navigator
  const publicKey: PublicKeyCredentialCreationOptions = {
    ...creationOptionsJSON.publicKey,
    challenge: toUint8Array(creationOptionsJSON.publicKey.challenge),
    user: {
      ...creationOptionsJSON.publicKey.user,
      id: toUint8Array(creationOptionsJSON.publicKey.user.id),
    },
    excludeCredentials: creationOptionsJSON.publicKey.excludeCredentials?.map(
      ({ id, transports }) => toPublicKeyCredentialDescriptor(id, transports)
    ),
  };

  // Wait for the user to complete attestation
  const credential = await navigator.credentials.create({ publicKey }) as PublicKeyCredential | null;

  if (!credential) {
    throw new Error('Attestation was not completed');
  }

  const response = credential.response as AuthenticatorAttestationResponse

  // Convert values to base64 to make it easier to send back to the server
  return {
    base64AttestationObject: toBase64String(response.attestationObject),
    base64ClientDataJSON: toBase64String(response.clientDataJSON),
  };
}
