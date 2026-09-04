import { AsnParser } from '@peculiar/asn1-schema';
import { Certificate } from '@peculiar/asn1-x509';
import { ECParameters, id_ecPublicKey, id_secp256r1, id_secp384r1 } from '@peculiar/asn1-ecc';
import { id_ml_dsa_44, id_ml_dsa_65, id_ml_dsa_87 } from '@peculiar/asn1-x509-post-quantum';
import { id_rsaEncryption, RSAPublicKey } from '@peculiar/asn1-rsa';

import {
  COSEALG,
  COSECRV,
  COSEKEYS,
  COSEKTY,
  type COSEPublicKey,
  type COSEPublicKeyAKP,
  type COSEPublicKeyEC2,
  type COSEPublicKeyRSA,
} from './cose.ts';
import { mapX509SignatureAlgToCOSEAlg } from './mapX509SignatureAlgToCOSEAlg.ts';
import type { Uint8Array_ } from '../types/index.ts';

export function convertX509PublicKeyToCOSE(
  x509Certificate: Uint8Array_,
): COSEPublicKey {
  let cosePublicKey: COSEPublicKey = new Map();

  /**
   * Time to extract the public key from an X.509 certificate
   */
  const x509 = AsnParser.parse(x509Certificate, Certificate);

  const { tbsCertificate } = x509;
  const { subjectPublicKeyInfo } = tbsCertificate;

  const publicKeyAlgorithmID = subjectPublicKeyInfo.algorithm.algorithm;

  if (publicKeyAlgorithmID === id_ecPublicKey) {
    /**
     * EC2 Public Key
     */
    if (!subjectPublicKeyInfo.algorithm.parameters) {
      throw new Error('Certificate public key was missing parameters (EC2)');
    }

    const ecParameters = AsnParser.parse(
      new Uint8Array(subjectPublicKeyInfo.algorithm.parameters),
      ECParameters,
    );

    let alg: COSEALG;
    let crv: number;
    const { namedCurve } = ecParameters;

    if (namedCurve === id_secp256r1) {
      alg = COSEALG.ES256;
      crv = COSECRV.P256;
    } else if (namedCurve === id_secp384r1) {
      alg = COSEALG.ES384;
      crv = COSECRV.P384;
    } else {
      throw new Error(
        `Certificate public key contained unexpected namedCurve ${namedCurve} (EC2)`,
      );
    }

    const subjectPublicKey = new Uint8Array(subjectPublicKeyInfo.subjectPublicKey);

    let x: Uint8Array_;
    let y: Uint8Array_;
    if (subjectPublicKey[0] === 0x04) {
      // Public key is in "uncompressed form", so we can split the remaining bytes in half
      let pointer = 1;
      const halfLength = (subjectPublicKey.length - 1) / 2;
      x = subjectPublicKey.slice(pointer, pointer += halfLength);
      y = subjectPublicKey.slice(pointer);
    } else {
      throw new Error(
        'TODO: Figure out how to handle public keys in "compressed form"',
      );
    }

    const coseEC2PubKey: COSEPublicKeyEC2 = new Map();
    coseEC2PubKey.set(COSEKEYS.kty, COSEKTY.EC2);
    coseEC2PubKey.set(COSEKEYS.alg, alg);
    coseEC2PubKey.set(COSEKEYS.crv, crv);
    coseEC2PubKey.set(COSEKEYS.x, x);
    coseEC2PubKey.set(COSEKEYS.y, y);

    cosePublicKey = coseEC2PubKey;
  } else if (publicKeyAlgorithmID === id_rsaEncryption) {
    /**
     * RSA public key
     */
    const rsaPublicKey = AsnParser.parse(
      subjectPublicKeyInfo.subjectPublicKey,
      RSAPublicKey,
    );

    const coseRSAPubKey: COSEPublicKeyRSA = new Map();
    coseRSAPubKey.set(COSEKEYS.kty, COSEKTY.RSA);
    /**
     * The algorithm ID is too ambiguous to know what this alg should really be. But practically
     * speaking `shaHashOverride` is always specified when verifying signatures with RSA public keys
     * which ultimately overrides this sensible default. Using RS256 also gets the correct WebCrypto
     * alg name later on in verifyRSA.ts
     */
    coseRSAPubKey.set(COSEKEYS.alg, COSEALG.RS256);
    coseRSAPubKey.set(COSEKEYS.n, new Uint8Array(rsaPublicKey.modulus));
    coseRSAPubKey.set(COSEKEYS.e, new Uint8Array(rsaPublicKey.publicExponent));

    cosePublicKey = coseRSAPubKey;
  } else if ([id_ml_dsa_44, id_ml_dsa_65, id_ml_dsa_87].indexOf(publicKeyAlgorithmID) >= 0) {
    const coseAKPPubKey: COSEPublicKeyAKP = new Map();
    coseAKPPubKey.set(COSEKEYS.kty, COSEKTY.AKP);
    coseAKPPubKey.set(COSEKEYS.alg, mapX509SignatureAlgToCOSEAlg(publicKeyAlgorithmID));
    coseAKPPubKey.set(COSEKEYS.pub, new Uint8Array(subjectPublicKeyInfo.subjectPublicKey));

    cosePublicKey = coseAKPPubKey;
  } else {
    throw new Error(
      `Certificate public key contained unexpected algorithm ID ${publicKeyAlgorithmID}`,
    );
  }

  return cosePublicKey;
}
