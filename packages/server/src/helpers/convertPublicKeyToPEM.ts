import jwkToPem from 'jwk-to-pem';

import { COSEKEYS, COSEKTY, coseCRV, COSEPublicKey } from './convertCOSEtoPKCS';
import { isoBase64URL, isoCBOR } from './iso';

export function convertPublicKeyToPEM(publicKey: Uint8Array): string {
  let struct;
  try {
    struct = isoCBOR.decodeFirst<COSEPublicKey>(publicKey);
  } catch (err) {
    const _err = err as Error;
    throw new Error(`Error decoding public key while converting to PEM: ${_err.message}`);
  }

  const kty = struct.get(COSEKEYS.kty);

  if (!kty) {
    throw new Error('Public key was missing kty');
  }

  if (kty === COSEKTY.EC2) {
    const crv = struct.get(COSEKEYS.crv);
    const x = struct.get(COSEKEYS.x);
    const y = struct.get(COSEKEYS.y);

    if (!crv) {
      throw new Error('Public key was missing crv (EC2)');
    }

    if (!x) {
      throw new Error('Public key was missing x (EC2)');
    }

    if (!y) {
      throw new Error('Public key was missing y (EC2)');
    }

    const ecPEM = jwkToPem({
      kty: 'EC',
      // Specify curve as "P-256" from "p256"
      crv: coseCRV[crv as number].replace('p', 'P-'),
      x: isoBase64URL.fromBuffer(x as Uint8Array, 'base64'),
      y: isoBase64URL.fromBuffer(y as Uint8Array, 'base64'),
    });

    return ecPEM;
  } else if (kty === COSEKTY.RSA) {
    const n = struct.get(COSEKEYS.n);
    const e = struct.get(COSEKEYS.e);

    if (!n) {
      throw new Error('Public key was missing n (RSA)');
    }

    if (!e) {
      throw new Error('Public key was missing e (RSA)');
    }

    const rsaPEM = jwkToPem({
      kty: 'RSA',
      n: isoBase64URL.fromBuffer(n as Uint8Array, 'base64'),
      e: isoBase64URL.fromBuffer(e as Uint8Array, 'base64'),
    });

    return rsaPEM;
  }

  throw new Error(`Could not convert public key type ${kty} to PEM`);
}
