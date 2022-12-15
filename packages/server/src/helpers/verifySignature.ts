import { COSEALG, COSEPublicKey } from './cose';
import { isoCrypto } from './iso';
import { decodeCredentialPublicKey } from './decodeCredentialPublicKey';
import { convertX509PublicKeyToCOSE } from './convertX509PublicKeyToCOSE';

/**
 * Verify an authenticator's signature
 */
export async function verifySignature(opts: {
  signature: Uint8Array;
  data: Uint8Array;
  credentialPublicKey?: Uint8Array;
  x509Certificate?: Uint8Array;
  hashAlgorithm?: COSEALG;
}): Promise<boolean> {
  const { signature, data, credentialPublicKey, x509Certificate, hashAlgorithm } = opts;

  if (!x509Certificate && !credentialPublicKey) {
    throw new Error('Must declare either "leafCert" or "credentialPublicKey"');
  }

  if (x509Certificate && credentialPublicKey) {
    throw new Error('Must not declare both "leafCert" and "credentialPublicKey"');
  }

  let cosePublicKey: COSEPublicKey = new Map();

  if (credentialPublicKey) {
    cosePublicKey = decodeCredentialPublicKey(credentialPublicKey);
  } else if (x509Certificate) {
    cosePublicKey = convertX509PublicKeyToCOSE(x509Certificate);
  }

  return isoCrypto.verify({
    cosePublicKey,
    signature,
    data,
    shaHashOverride: hashAlgorithm,
  });
}
