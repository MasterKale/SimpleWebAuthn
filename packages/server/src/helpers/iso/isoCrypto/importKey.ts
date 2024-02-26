import { getWebCrypto } from './getWebCrypto.ts';

export function importKey(opts: {
  keyData: JsonWebKey;
  algorithm: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams;
}): Promise<CryptoKey> {
  const WebCrypto = getWebCrypto();

  const { keyData, algorithm } = opts;

  return WebCrypto.subtle.importKey('jwk', keyData, algorithm, false, [
    'verify',
  ]);
}
