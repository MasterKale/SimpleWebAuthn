import { COSEALG, COSEPublicKey } from './cose.ts';
import { isoCrypto } from './iso/index.ts';
import { decodeCredentialPublicKey } from './decodeCredentialPublicKey.ts';
import { convertX509PublicKeyToCOSE } from './convertX509PublicKeyToCOSE.ts';
import type { Uint8Array_ } from '../types/index.ts';

/**
 * Verify an authenticator's signature
 */
export function verifySignature(opts: {
  signature: Uint8Array_;
  data: Uint8Array_;
  credentialPublicKey?: Uint8Array_;
  x509Certificate?: Uint8Array_;
  hashAlgorithm?: COSEALG;
}): Promise<boolean> {
  const {
    signature,
    data,
    credentialPublicKey,
    x509Certificate,
    hashAlgorithm,
  } = opts;

  if (!x509Certificate && !credentialPublicKey) {
    throw new Error('Must declare either "leafCert" or "credentialPublicKey"');
  }

  if (x509Certificate && credentialPublicKey) {
    throw new Error(
      'Must not declare both "leafCert" and "credentialPublicKey"',
    );
  }

  let cosePublicKey: COSEPublicKey = new Map();

  if (credentialPublicKey) {
    cosePublicKey = decodeCredentialPublicKey(credentialPublicKey);
  } else if (x509Certificate) {
    cosePublicKey = convertX509PublicKeyToCOSE(x509Certificate);
  }

  return _verifySignatureInternals.stubThis(
    isoCrypto.verify({
      cosePublicKey,
      signature,
      data,
      shaHashOverride: hashAlgorithm,
    }),
  );
}

/**
 * Make it possible to stub the return value during testing
 * @ignore Don't include this in docs output
 */
export const _verifySignatureInternals = {
  stubThis: (value: Promise<boolean>) => value,
};
