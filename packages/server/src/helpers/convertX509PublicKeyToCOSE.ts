import { AsnParser } from '@peculiar/asn1-schema';
import { Certificate } from '@peculiar/asn1-x509';
import { ECParameters, id_ecPublicKey, id_secp256r1 } from '@peculiar/asn1-ecc';
import { RSAPublicKey } from '@peculiar/asn1-rsa';

import { COSEPublicKey, COSEKTY, COSECRV, COSEKEYS, COSEPublicKeyEC2, COSEPublicKeyRSA, COSEALG } from "./cose";

export function convertX509PublicKeyToCOSE(leafCertificate: Uint8Array): COSEPublicKey {
  let cosePublicKey: COSEPublicKey = new Map();

  /**
   * Time to extract the public key from an X.509 leaf certificate
   */
  const x509 = AsnParser.parse(leafCertificate, Certificate);

  const { tbsCertificate } = x509;
  const {
    subjectPublicKeyInfo,
    signature: _tbsSignature,
  } = tbsCertificate;

  const signatureAlgorithm = _tbsSignature.algorithm;
  const publicKeyAlgorithmID = subjectPublicKeyInfo.algorithm.algorithm;

  if (publicKeyAlgorithmID === id_ecPublicKey) {
    /**
     * EC2 Public Key
     */
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

    const coseEC2PubKey: COSEPublicKeyEC2 = new Map();
    coseEC2PubKey.set(COSEKEYS.kty, COSEKTY.EC2);
    coseEC2PubKey.set(COSEKEYS.alg, signatureAlgorithmToCOSEAlg(signatureAlgorithm));
    coseEC2PubKey.set(COSEKEYS.crv, crv);
    coseEC2PubKey.set(COSEKEYS.x, x);
    coseEC2PubKey.set(COSEKEYS.y, y);

    cosePublicKey = coseEC2PubKey;
  } else if (publicKeyAlgorithmID === '1.2.840.113549.1.1.1') {
    /**
     * RSA public key
     */
    const rsaPublicKey = AsnParser.parse(subjectPublicKeyInfo.subjectPublicKey, RSAPublicKey);

    const coseRSAPubKey: COSEPublicKeyRSA = new Map();
    coseRSAPubKey.set(COSEKEYS.kty, COSEKTY.RSA);
    coseRSAPubKey.set(COSEKEYS.alg, signatureAlgorithmToCOSEAlg(signatureAlgorithm));
    coseRSAPubKey.set(COSEKEYS.n, new Uint8Array(rsaPublicKey.modulus));
    coseRSAPubKey.set(COSEKEYS.e, new Uint8Array(rsaPublicKey.publicExponent));

    cosePublicKey = coseRSAPubKey;
  } else {
    throw new Error(`Unexpected leaf cert public key algorithm ${publicKeyAlgorithmID}`);
  }

  return cosePublicKey;
}

/**
 * Map X.509 signature algorithm OIDs to COSE algorithm IDs
 *
 * - EC2 OIDs: https://oidref.com/1.2.840.10045.4.3
 * - RSA OIDs: https://oidref.com/1.2.840.113549.1.1
 */
function signatureAlgorithmToCOSEAlg(signatureAlgorithm: string): COSEALG {
  let alg: COSEALG;

  if (signatureAlgorithm === '1.2.840.10045.4.3.2') {
    alg = COSEALG.ES256;
  } else if (signatureAlgorithm === '1.2.840.10045.4.3.3') {
    alg = COSEALG.ES384;
  } else if (signatureAlgorithm === '1.2.840.10045.4.3.4') {
    alg = COSEALG.ES512;
  } else if (signatureAlgorithm === '1.2.840.113549.1.1.11') {
    alg = COSEALG.RS256;
  } else if (signatureAlgorithm === '1.2.840.113549.1.1.12') {
    alg = COSEALG.RS384;
  } else if (signatureAlgorithm === '1.2.840.113549.1.1.13') {
    alg = COSEALG.RS512;
  } else if (signatureAlgorithm === '1.2.840.113549.1.1.5') {
    alg = COSEALG.RS1;
  } else {
    throw new Error(
      `Leaf cert contained unexpected signature algorithm ${signatureAlgorithm} (EC2)`,
    );
  }

  return alg;
}
