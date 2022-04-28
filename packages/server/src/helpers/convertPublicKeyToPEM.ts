import cbor from 'cbor';
import jwkToPem from 'jwk-to-pem';

import { COSEKEYS, COSEKTY, COSECRV } from './convertCOSEtoPKCS';

export default function convertPublicKeyToPEM(publicKey: Buffer): string {
  let struct;
  try {
    struct = cbor.decodeAllSync(publicKey)[0];
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
      crv: COSECRV[crv as number].replace('p', 'P-'),
      x: (x as Buffer).toString('base64'),
      y: (y as Buffer).toString('base64'),
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
      n: (n as Buffer).toString('base64'),
      e: (e as Buffer).toString('base64'),
    });

    return rsaPEM;
  }

  throw new Error(`Could not convert public key type ${kty} to PEM`);
}
