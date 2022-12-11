import WebCrypto from '@simplewebauthn/iso-webcrypto';

import { COSEPublicKeyOKP, COSEKEYS, isCOSEAlg, COSECRV } from '../../cose';
import { isoBase64URL } from '../../index';
import { SubtleCryptoCrv } from './structs';
import { importKey } from './importKey';

export async function verifyOKP(opts: {
  cosePublicKey: COSEPublicKeyOKP;
  signature: Uint8Array;
  data: Uint8Array;
}): Promise<boolean> {
  const { cosePublicKey, signature, data } = opts;

  const alg = cosePublicKey.get(COSEKEYS.alg);
  const crv = cosePublicKey.get(COSEKEYS.crv);
  const x = cosePublicKey.get(COSEKEYS.x);

  if (!alg) {
    throw new Error('Public key was missing alg (OKP)');
  }

  if (!isCOSEAlg(alg)) {
    throw new Error(`Public key had invalid alg ${alg} (OKP)`);
  }

  if (!crv) {
    throw new Error('Public key was missing crv (OKP)');
  }

  if (!x) {
    throw new Error('Public key was missing x (OKP)');
  }

  // Pulled key import steps from here:
  // https://wicg.github.io/webcrypto-secure-curves/#ed25519-operations
  let _crv: SubtleCryptoCrv;
  if (crv === COSECRV.ED25519) {
    _crv = 'Ed25519';
  } else {
    throw new Error(`Unexpected COSE crv value of ${crv} (OKP)`);
  }

  const keyData: JsonWebKey = {
    kty: 'OKP',
    crv: _crv,
    alg: 'EdDSA',
    x: isoBase64URL.fromBuffer(x),
    ext: false,
  };

  const keyAlgorithm: EcKeyImportParams = {
    name: _crv,
    namedCurve: _crv,
  };

  const key = await importKey({
    keyData,
    algorithm: keyAlgorithm,
  });

  const verifyAlgorithm: AlgorithmIdentifier = {
    name: _crv,
  };

  return WebCrypto.subtle.verify(verifyAlgorithm, key, signature, data);
}
