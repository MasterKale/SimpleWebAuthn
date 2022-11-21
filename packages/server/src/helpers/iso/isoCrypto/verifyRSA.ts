import { webcrypto } from 'node:crypto';

import { COSEALG, COSEKEYS, COSEPublicKeyRSA, isCOSEAlg } from "../../cose";
import { mapCoseAlgToWebCryptoAlg } from "./mapCoseAlgToWebCryptoAlg";
import { importKey } from './importKey';
import { isoBase64URL } from '../index';
import { mapCoseAlgToWebCryptoKeyAlgName } from './mapCoseAlgToWebCryptoKeyAlgName';

/**
 *
 */
export async function verifyRSA(opts: {
  cosePublicKey: COSEPublicKeyRSA,
  signature: Uint8Array,
  data: Uint8Array,
  shaHashOverride?: COSEALG,
}): Promise<boolean> {
  const { cosePublicKey, signature, data, shaHashOverride } = opts;

  const alg = cosePublicKey.get(COSEKEYS.alg);
  const n = cosePublicKey.get(COSEKEYS.n);
  const e = cosePublicKey.get(COSEKEYS.e);

  if (!alg) {
    throw new Error('Public key was missing alg (RSA)');
  }

  if (!isCOSEAlg(alg)) {
    throw new Error(`Public key had invalid alg ${alg} (RSA)`);
  }

  if (!n) {
    throw new Error('Public key was missing n (RSA)');
  }

  if (!e) {
    throw new Error('Public key was missing e (RSA)');
  }

  const keyData: JsonWebKey = {
    kty: 'RSA',
    alg: '',
    n: isoBase64URL.fromBuffer(n),
    e: isoBase64URL.fromBuffer(e),
    ext: false,
  };

  const keyAlgorithm = {
    name: mapCoseAlgToWebCryptoKeyAlgName(alg),
    hash: { name: mapCoseAlgToWebCryptoAlg(alg) },
  };

  if (shaHashOverride) {
    keyAlgorithm.hash.name = mapCoseAlgToWebCryptoAlg(shaHashOverride);
  }

  if (keyAlgorithm.name === 'RSASSA-PKCS1-v1_5') {
    if (keyAlgorithm.hash.name === 'SHA-256') {
      keyData.alg = 'RS256';
    } else if (keyAlgorithm.hash.name === 'SHA-384') {
      keyData.alg = 'RS384';
    } else if (keyAlgorithm.hash.name === 'SHA-512') {
      keyData.alg = 'RS512';
    } else if (keyAlgorithm.hash.name === 'SHA-1') {
      keyData.alg = 'RS1';
    }
  } else if (keyAlgorithm.name === 'RSA-PSS') {
    if (keyAlgorithm.hash.name === 'SHA-256') {
      keyData.alg = 'PS256';
    } else if (keyAlgorithm.hash.name === 'SHA-384') {
      keyData.alg = 'PS384';
    } else if (keyAlgorithm.hash.name === 'SHA-512') {
      keyData.alg = 'PS512';
    }
  } else {
    throw new Error(`Unexpected RSA key algorithm ${alg} (${keyAlgorithm.name})`);
  }

  const key = await importKey({
    keyData,
    algorithm: keyAlgorithm,
  });

  const verifyAlgorithm = {
    // TODO: Determine this from `alg` so we might support the rarer RSA-PSS
    name: 'RSASSA-PKCS1-v1_5',
  };
  if (globalThis.crypto) {
    return globalThis.crypto.subtle.verify(verifyAlgorithm, key, signature, data);
  } else {
    return webcrypto.subtle.verify(verifyAlgorithm, key, signature, data);
  }
}
