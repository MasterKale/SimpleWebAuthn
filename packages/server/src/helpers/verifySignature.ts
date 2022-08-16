import crypto from 'crypto';
import cbor from 'cbor';
import { verify as ed25519Verify } from '@noble/ed25519';

import { COSEKEYS, COSEKTY } from './convertCOSEtoPKCS';
import { convertCertBufferToPEM } from './convertCertBufferToPEM';
import { convertPublicKeyToPEM } from './convertPublicKeyToPEM';

type VerifySignatureOptsLeafCert = {
  signature: Buffer,
  signatureBase: Buffer,
  leafCert: Buffer,
  hashAlgorithm?: string,
};

type VerifySignatureOptsCredentialPublicKey = {
  signature: Buffer,
  signatureBase: Buffer,
  credentialPublicKey: Buffer,
  hashAlgorithm?: string,
};

/**
 * Verify an authenticator's signature
 *
 * @param signature attStmt.sig
 * @param signatureBase Output from Buffer.concat()
 * @param publicKey Authenticator's public key as a PEM certificate
 * @param algo Which algorithm to use to verify the signature (default: `'sha256'`)
 */
export async function verifySignature(opts: VerifySignatureOptsLeafCert | VerifySignatureOptsCredentialPublicKey): Promise<boolean> {
  const {
    signature,
    signatureBase,
    hashAlgorithm = 'sha256',
  } = opts;
  const _isLeafcertOpts = isLeafCertOpts(opts);
  const _isCredPubKeyOpts = isCredPubKeyOpts(opts);

  if (!_isLeafcertOpts && !_isCredPubKeyOpts) {
    throw new Error('Must declare either `leafCert` or `credentialPublicKey`')
  }

  if (_isLeafcertOpts && _isCredPubKeyOpts) {
    throw new Error('Must not declare both `leafCert` and `credentialPublicKey`');
  }

  let publicKeyPEM = '';

  if (_isCredPubKeyOpts) {
    const { credentialPublicKey } = opts;

    // Decode CBOR to COSE
    let struct;
    try {
      struct = cbor.decodeAllSync(credentialPublicKey)[0];
    } catch (err) {
      const _err = err as Error;
      throw new Error(`Error decoding public key while converting to PEM: ${_err.message}`);
    }

    const kty = struct.get(COSEKEYS.kty);

    if (!kty) {
      throw new Error('Public key was missing kty');
    }

    // Check key type
    if (kty === COSEKTY.OKP) {
      // Verify Ed25519 slightly differently
      const x = struct.get(COSEKEYS.x);

      if (!x) {
        throw new Error('Public key was missing x (OKP)');
      }

      return ed25519Verify(signature, signatureBase, x);
    } else {
      // Convert pubKey to PEM for ECC and RSA
      publicKeyPEM = convertPublicKeyToPEM(credentialPublicKey);
    }
  }

  if (_isLeafcertOpts) {
    const { leafCert } = opts;
    publicKeyPEM = convertCertBufferToPEM(leafCert);
  }

  return crypto.createVerify(hashAlgorithm).update(signatureBase).verify(publicKeyPEM, signature);
}

function isLeafCertOpts(opts: VerifySignatureOptsLeafCert | VerifySignatureOptsCredentialPublicKey): opts is VerifySignatureOptsLeafCert {
  return Object.keys(opts as VerifySignatureOptsLeafCert).indexOf('leafCert') >= 0;
}

function isCredPubKeyOpts(opts: VerifySignatureOptsLeafCert | VerifySignatureOptsCredentialPublicKey): opts is VerifySignatureOptsCredentialPublicKey {
  return Object.keys(opts as VerifySignatureOptsCredentialPublicKey).indexOf('credentialPublicKey') >= 0;
}
