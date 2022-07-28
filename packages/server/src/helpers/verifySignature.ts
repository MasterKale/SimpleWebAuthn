import crypto from 'crypto';

/**
 * Verify an authenticator's signature
 *
 * @param signature attStmt.sig
 * @param signatureBase Output from Buffer.concat()
 * @param publicKey Authenticator's public key as a PEM certificate
 * @param algo Which algorithm to use to verify the signature (default: `'sha256'`)
 */
export function verifySignature(
  signature: Buffer,
  signatureBase: Buffer,
  publicKey: string,
  algo = 'sha256',
): boolean {
  return crypto.createVerify(algo).update(signatureBase).verify(publicKey, signature);
}
