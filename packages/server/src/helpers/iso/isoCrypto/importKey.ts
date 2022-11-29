import WebCrypto from '@simplewebauthn/iso-webcrypto';

export async function importKey(opts: {
  keyData: JsonWebKey;
  algorithm: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams;
}): Promise<CryptoKey> {
  const { keyData, algorithm } = opts;

  return WebCrypto.subtle.importKey('jwk', keyData, algorithm, false, ['verify']);
}
