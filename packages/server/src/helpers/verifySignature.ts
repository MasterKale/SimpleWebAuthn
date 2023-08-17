import { COSEALG, COSEPublicKey } from "./cose.ts";
import { isoCrypto } from "./iso/index.ts";
import { decodeCredentialPublicKey } from "./decodeCredentialPublicKey.ts";
import { convertX509PublicKeyToCOSE } from "./convertX509PublicKeyToCOSE.ts";

/**
 * Verify an authenticator's signature
 */
export function verifySignature(opts: {
  signature: Uint8Array;
  data: Uint8Array;
  credentialPublicKey?: Uint8Array;
  x509Certificate?: Uint8Array;
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

// Make it possible to stub the return value during testing
export const _verifySignatureInternals = {
  stubThis: (value: Promise<boolean>) => value,
};
