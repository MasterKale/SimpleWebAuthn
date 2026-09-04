import { COSEKEYS, type COSEPublicKeyAKP, isCOSEAlg } from '../../cose.ts';
import { isoBase64URL } from '../../index.ts';
import { importJWKKey } from './importJWKKey.ts';
import { getWebCrypto } from './getWebCrypto.ts';
import { mapCoseAlgToWebCryptoKeyAlgName } from './mapCoseAlgToWebCryptoKeyAlgName.ts';
import { PQCNotSupportedError } from '../../../errors/index.ts';
import type { Base64URLString, Uint8Array_ } from '../../../types/index.ts';

/** AKP, a.k.a ML-DSA */
export async function verifyAKP(opts: {
  cosePublicKey: COSEPublicKeyAKP;
  signature: Uint8Array_;
  data: Uint8Array_;
}): Promise<boolean> {
  const { cosePublicKey, signature, data } = opts;

  const WebCrypto = await getWebCrypto();

  const alg = cosePublicKey.get(COSEKEYS.alg);
  const pub = cosePublicKey.get(COSEKEYS.pub);

  if (!alg) {
    throw new Error('Public key was missing alg (AKP)');
  }

  if (!isCOSEAlg(alg)) {
    throw new Error(`Public key had invalid alg ${alg} (AKP)`);
  }

  if (!pub) {
    throw new Error('Public key was missing pub (AKP)');
  }

  const webCryptoAlg = mapCoseAlgToWebCryptoKeyAlgName(alg);

  // See https://wicg.github.io/webcrypto-modern-algos/#ml-dsa-operations-import-key -> "jwk"
  const keyData: JsonWebKeyAKP = {
    kty: 'AKP',
    alg: webCryptoAlg,
    pub: isoBase64URL.fromBuffer(pub),
    ext: false,
  };

  /**
   * ML-DSA support is pretty cutting edge, so take some steps to help RP's understand this instead
   * of them getting a `NotSupportedError: Unrecognized algorithm name` and trying to interpret it.
   */
  let key: Awaited<ReturnType<typeof importJWKKey>>;
  try {
    key = await importJWKKey({ keyData, algorithm: webCryptoAlg });
  } catch (err) {
    const _err = err as Error;
    if (_err.name === 'NotSupportedError') {
      throw new PQCNotSupportedError(alg);
    } else {
      throw err;
    }
  }

  return WebCrypto.subtle.verify(webCryptoAlg, key, signature, data);
}

type JsonWebKeyAKP = JsonWebKey & {
  // https://www.rfc-editor.org/rfc/rfc9964.html#section-8.1.6.1
  pub?: Base64URLString;
};
