import crypto from 'crypto';

/**
 * Verify an authenticator's signature
 *
 * @param signature attStmt.sig
 * @param signatureBase Output from Buffer.concat()
 * @param publicKey Authenticator's public key as a PEM certificate
 */
export default function verifySignature(
  signature: Buffer,
  signatureBase: Buffer,
  publicKey: string,
): boolean {
  return crypto.createVerify('SHA256').update(signatureBase).verify(publicKey, signature);
}
