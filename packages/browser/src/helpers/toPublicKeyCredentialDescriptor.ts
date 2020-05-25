import base64js from 'base64-js';

/**
 * A helper method to convert a base64 encoded credential id into a PublicKeyCredentialDescriptor,
 * which is usable by allowCredentials and excludeCredentials.
 */
export default function toPublicKeyCredentialDescriptor(
    base64CredentialId: string,
    transports?: AuthenticatorTransport[]
): PublicKeyCredentialDescriptor {
    // Pad id with = characters until it is a multiple of 4 so it is a proper base64 encoded string.
    // This is required because credential.id returned by navigor.credentials.get/create is base64 encoded but not padded.
    const padLength = 4 - base64CredentialId.length % 4;
    base64CredentialId = base64CredentialId.padEnd(base64CredentialId.length + padLength, '=');

    return {
      type: 'public-key',
      id: base64js.toByteArray(base64CredentialId),
      transports
    };
}
  