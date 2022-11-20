import { webcrypto } from 'node:crypto';

export async function importKey(opts: {
  keyData: JsonWebKey,
  algorithm: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams,
}): Promise<CryptoKey> {
  const { keyData, algorithm } = opts;

  if (globalThis.crypto) {
    return globalThis.crypto.subtle.importKey('jwk', keyData, algorithm, false, ['verify']);
  } else {
    return webcrypto.subtle.importKey('jwk', keyData, algorithm, false, ['verify']);
  }
}
