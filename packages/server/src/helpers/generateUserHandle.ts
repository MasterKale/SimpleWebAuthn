import crypto from 'crypto';

/**
 * Generate a suitably random value to be used as a user handle when creating a credential
 */
export default function generateUserHandle(): Buffer {
  /**
   * As per WebAuthn spec:
   *
   * "A user handle is an opaque byte sequence with a maximum size of 64 bytes, and is not meant to
   * be displayed to the user."
   *
   * See https://w3c.github.io/webauthn/#user-handle
   */
  return crypto.randomBytes(64);
}
