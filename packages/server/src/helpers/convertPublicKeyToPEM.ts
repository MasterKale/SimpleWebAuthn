import cbor from 'cbor';
import jwkToPem from 'jwk-to-pem';
import base64url from 'base64url';

import { COSEKEYS, COSEKTY, COSECRV } from './convertCOSEtoPKCS';
import convertX509CertToPEM from './convertX509CertToPEM';

export default function convertPublicKeyToPEM(publicKey: string): string {
  const publicKeyBuffer = base64url.toBuffer(publicKey);
  console.log(publicKeyBuffer.toString('hex'));

  let struct;
  try {
    struct = cbor.decodeAllSync(publicKeyBuffer)[0];
  } catch (err) {
    console.warn('Caught error when trying to decode public key, might be an old public key');
    /**
     * Catching an error here means we're probably converting an "old" EC2 public key that was
     * saved before we started returning the full credentialPublicKey from an attestation.
     *
     * We're playing things a little fast and loose by naively converting it to PEM format in a way
     * that is consistent with how it used to be constructed.
     *
     * BTW this is in here to try and prevent better RSA support from breaking existing deployments.
     * It is strongly recommended that this be deprecated in a future release...
     */
    let oldPubKeyPEM = convertX509CertToPEM(
      Buffer.concat([
        // Assumes EC keyType with P-256 algorithm
        Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'),
        publicKeyBuffer,
      ]),
    );

    // Replace "-----BEGIN CERTIFICATE-----" with "-----BEGIN PUBLIC KEY-----" (so we can reuse
    // the method)
    oldPubKeyPEM = oldPubKeyPEM.replace(/CERTIFICATE/gi, 'PUBLIC KEY');

    return oldPubKeyPEM;
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
