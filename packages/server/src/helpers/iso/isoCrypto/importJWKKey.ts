import { getWebCrypto } from './getWebCrypto.ts';

/**
 * Convert a JWK-formatted public key into a WebCrypto CryptoKey that can be used for
 * signature verification
 */
export async function importJWKKey(opts: {
  keyData: JsonWebKey;
  algorithm: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams;
}): Promise<CryptoKey> {
  const WebCrypto = await getWebCrypto();

  const { keyData, algorithm } = opts;

  return WebCrypto.subtle.importKey('jwk', keyData, algorithm, false, ['verify']);
}
