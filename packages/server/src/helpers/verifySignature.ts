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
  leafCertificate?: Uint8Array;
  attestationHashAlgorithm?: COSEALG;
}): Promise<boolean> {
  const { signature, data, credentialPublicKey, leafCertificate, attestationHashAlgorithm } = opts;

  if (!leafCertificate && !credentialPublicKey) {
    throw new Error('Must declare either "leafCert" or "credentialPublicKey"');
  }

  if (leafCertificate && credentialPublicKey) {
    throw new Error('Must not declare both "leafCert" and "credentialPublicKey"');
  }

  let cosePublicKey: COSEPublicKey = new Map();

  if (credentialPublicKey) {
    cosePublicKey = decodeCredentialPublicKey(credentialPublicKey);
  } else if (leafCertificate) {
    cosePublicKey = convertX509PublicKeyToCOSE(leafCertificate);
  }

  return isoCrypto.verify({
    cosePublicKey,
    signature,
    data,
    shaHashOverride: attestationHashAlgorithm,
  });
}
