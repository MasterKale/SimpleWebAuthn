/* eslint-disable @typescript-eslint/ban-ts-comment */
import { verify as ed25519Verify } from '@noble/ed25519';
import { AsnParser } from '@peculiar/asn1-schema';
import { Certificate } from '@peculiar/asn1-x509';
import { ECParameters, id_ecPublicKey, id_secp256r1 } from '@peculiar/asn1-ecc';
import { RSAPublicKey } from '@peculiar/asn1-rsa';

import { COSECRV, COSEKEYS, COSEKTY, COSEPublicKey } from './convertCOSEtoPKCS';
import { isoCrypto } from './iso';
import { decodeCredentialPublicKey } from './decodeCredentialPublicKey';

type VerifySignatureOptsLeafCert = {
  signature: Uint8Array;
  signatureBase: Uint8Array;
  leafCert: Uint8Array;
  rsaHashAlgorithm?: string;
};

type VerifySignatureOptsCredentialPublicKey = {
  signature: Uint8Array;
  signatureBase: Uint8Array;
  publicKey: Uint8Array;
  rsaHashAlgorithm?: string;
};

/**
 * Verify an authenticator's signature
 *
 * @param signature attStmt.sig
 * @param signatureBase Bytes that were signed over
 * @param publicKey Authenticator's public key as a PEM certificate
 * @param rsaHashAlgorithm Which algorithm to use to verify RSA signatures
 */
export async function verifySignature(
  opts: VerifySignatureOptsLeafCert | VerifySignatureOptsCredentialPublicKey,
): Promise<boolean> {
  const { signature, signatureBase, rsaHashAlgorithm } = opts;
  const _isLeafcertOpts = isLeafCertOpts(opts);
  const _isCredPubKeyOpts = isCredPubKeyOpts(opts);

  if (!_isLeafcertOpts && !_isCredPubKeyOpts) {
    throw new Error('Must declare either "leafCert" or "credentialPublicKey"');
  }

  if (_isLeafcertOpts && _isCredPubKeyOpts) {
    throw new Error('Must not declare both "leafCert" and "credentialPublicKey"');
  }

  let subtlePublicKey: CryptoKey;
  let kty: COSEKTY;
  let alg: number;

  if (_isCredPubKeyOpts) {
    const { publicKey } = opts;

    const cosePublicKey = decodeCredentialPublicKey(publicKey);

    const _kty = cosePublicKey.get(COSEKEYS.kty);
    const _alg = cosePublicKey.get(COSEKEYS.alg);

    if (!_kty) {
      throw new Error('Public key was missing kty');
    }

    if (!_alg) {
      throw new Error('Public key was missing alg');
    }

    // Verify Ed25519 slightly differently
    if (_kty === COSEKTY.OKP) {
      const x = cosePublicKey.get(COSEKEYS.x);

      if (!x) {
        throw new Error('Public key was missing x (OKP)');
      }

      return ed25519Verify(signature, signatureBase, (x as Uint8Array));
    }

    // Assume we're handling COSEKTY.EC2 or COSEKTY.RSA key from here on
    subtlePublicKey = await isoCrypto.importKey(cosePublicKey);
    kty = _kty as COSEKTY;
    alg = _alg as number;
  } else if (_isLeafcertOpts) {
    /**
     * Time to extract the public key from an X.509 leaf certificate
     */
    const { leafCert } = opts;

    const x509 = AsnParser.parse(leafCert, Certificate);

    const { tbsCertificate } = x509;
    const {
      subjectPublicKeyInfo,
      signature: _tbsSignature,
    } = tbsCertificate;

    // console.log(tbsCertificate);

    const signatureAlgorithm = _tbsSignature.algorithm;
    const publicKeyAlgorithmID = subjectPublicKeyInfo.algorithm.algorithm;

    if (publicKeyAlgorithmID === id_ecPublicKey) {
      /**
       * EC2 Public Key
       */
      kty = COSEKTY.EC2;

      if (!subjectPublicKeyInfo.algorithm.parameters) {
        throw new Error('Leaf cert public key missing parameters (EC2)');
      }

      const ecParameters = AsnParser.parse(new Uint8Array(subjectPublicKeyInfo.algorithm.parameters), ECParameters);

      let crv = -999;
      if (ecParameters.namedCurve === id_secp256r1) {
        crv = COSECRV.P256;
      } else {
        throw new Error(
          `Leaf cert public key contained unexpected namedCurve ${ecParameters.namedCurve} (EC2)`,
        );
      }

      const subjectPublicKey = new Uint8Array(subjectPublicKeyInfo.subjectPublicKey)

      let x: Uint8Array;
      let y: Uint8Array;
      if (subjectPublicKey[0] === 0x04) {
        // Public key is in "uncompressed form", so we can split the remaining bytes in half
        let pointer = 1;
        const halfLength = (subjectPublicKey.length - 1) / 2;
        x = subjectPublicKey.slice(pointer, pointer += halfLength);
        y = subjectPublicKey.slice(pointer);
      } else {
        throw new Error('TODO: Figure out how to handle public keys in "compressed form"');
      }

      const coseEC2PubKey: COSEPublicKey = new Map();
      coseEC2PubKey.set(COSEKEYS.kty, COSEKTY.EC2);
      coseEC2PubKey.set(COSEKEYS.crv, crv);
      coseEC2PubKey.set(COSEKEYS.x, x);
      coseEC2PubKey.set(COSEKEYS.y, y);

      subtlePublicKey = await isoCrypto.importKey(coseEC2PubKey);
      alg = -7;
    } else if (publicKeyAlgorithmID === '1.2.840.113549.1.1.1') {
      /**
       * RSA public key
       */
      kty = COSEKTY.RSA;
      const rsaPublicKey = AsnParser.parse(subjectPublicKeyInfo.subjectPublicKey, RSAPublicKey);

      let _alg = -999;
      if (signatureAlgorithm === '1.2.840.113549.1.1.11') {
        _alg = -257; // RS256
      } else if (signatureAlgorithm === '1.2.840.113549.1.1.12') {
        _alg = -258; // RS384
      } else if (signatureAlgorithm === '1.2.840.113549.1.1.13') {
        _alg = -259; // RS512
      } else {
        throw new Error(
          `Leaf cert contained unexpected signature algorithm ${signatureAlgorithm} (RSA)`,
        );
      }

      const coseRSAPubKey: COSEPublicKey = new Map();
      coseRSAPubKey.set(COSEKEYS.kty, COSEKTY.RSA);
      coseRSAPubKey.set(COSEKEYS.alg, _alg);
      coseRSAPubKey.set(COSEKEYS.n, new Uint8Array(rsaPublicKey.modulus));
      coseRSAPubKey.set(COSEKEYS.e, new Uint8Array(rsaPublicKey.publicExponent));

      subtlePublicKey = await isoCrypto.importKey(coseRSAPubKey, rsaHashAlgorithm);
      alg = _alg;
    } else {
      throw new Error(`Unexpected leaf cert public key algorithm ${publicKeyAlgorithmID}`);
    }
  } else {
    throw new Error(
      'How did we get here? We were supposed to make sure we were only dealing with one of two possible sets of method arguments!!',
    );
  }

  if (
    // @ts-ignore 2454
    typeof subtlePublicKey === 'undefined'
    // @ts-ignore 2454
    || typeof kty === 'undefined'
    // @ts-ignore 2454
    || typeof alg === 'undefined'
  ) {
      throw new Error('You must import a public key, and determine kty and alg before proceeding');
  }

  return isoCrypto.verify({
    publicKey: subtlePublicKey,
    coseKty: kty,
    coseAlg: alg,
    signature,
    data: signatureBase,
  });
}

function isLeafCertOpts(
  opts: VerifySignatureOptsLeafCert | VerifySignatureOptsCredentialPublicKey,
): opts is VerifySignatureOptsLeafCert {
  return Object.keys(opts as VerifySignatureOptsLeafCert).indexOf('leafCert') >= 0;
}

function isCredPubKeyOpts(
  opts: VerifySignatureOptsLeafCert | VerifySignatureOptsCredentialPublicKey,
): opts is VerifySignatureOptsCredentialPublicKey {
  return (
    Object.keys(opts as VerifySignatureOptsCredentialPublicKey).indexOf('publicKey') >= 0
  );
}
