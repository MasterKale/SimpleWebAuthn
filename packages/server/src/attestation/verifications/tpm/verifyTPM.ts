import { AsnParser } from '@peculiar/asn1-schema';
import { Certificate, id_ce_subjectAltName, SubjectAlternativeName } from '@peculiar/asn1-x509';

import type { AttestationStatement } from '../../../helpers/decodeAttestationObject';
import decodeCredentialPublicKey from '../../../helpers/decodeCredentialPublicKey';
import { COSEKEYS, COSEALGHASH } from '../../../helpers/convertCOSEtoPKCS';
import toHash from '../../../helpers/toHash';
import convertASN1toPEM from '../../../helpers/convertASN1toPEM';
import getCertificateInfo from '../../../helpers/getCertificateInfo';
import verifySignature from '../../../helpers/verifySignature';
import { leafCertToASN1Object, findOID, JASN1, ASN1Object } from '../../../helpers/asn1Utils';
import MetadataService from '../../../metadata/metadataService';
import verifyAttestationWithMetadata from '../../../metadata/verifyAttestationWithMetadata';

import { TPM_ECC_CURVE, TPM_MANUFACTURERS } from './constants';
import parseCertInfo from './parseCertInfo';
import parsePubArea from './parsePubArea';

type Options = {
  aaguid: Buffer;
  attStmt: AttestationStatement;
  authData: Buffer;
  credentialPublicKey: Buffer;
  clientDataHash: Buffer;
};

export default async function verifyTPM(options: Options): Promise<boolean> {
  const { aaguid, attStmt, authData, credentialPublicKey, clientDataHash } = options;
  const { ver, sig, alg, x5c, pubArea, certInfo } = attStmt;

  /**
   * Verify structures
   */
  if (ver !== '2.0') {
    throw new Error(`Unexpected ver "${ver}", expected "2.0" (TPM)`);
  }

  if (!sig) {
    throw new Error('No attestation signature provided in attestation statement (TPM)');
  }

  if (!alg) {
    throw new Error(`Attestation statement did not contain alg (TPM)`);
  }

  if (!x5c) {
    throw new Error('No attestation certificate provided in attestation statement (TPM)');
  }

  if (!pubArea) {
    throw new Error('Attestation statement did not contain pubArea (TPM)');
  }

  if (!certInfo) {
    throw new Error('Attestation statement did not contain certInfo (TPM)');
  }

  const parsedPubArea = parsePubArea(pubArea);
  const { unique, type: pubType, parameters } = parsedPubArea;

  // Verify that the public key specified by the parameters and unique fields of pubArea is
  // identical to the credentialPublicKey in the attestedCredentialData in authenticatorData.
  const cosePublicKey = decodeCredentialPublicKey(credentialPublicKey);

  if (pubType === 'TPM_ALG_RSA') {
    const n = cosePublicKey.get(COSEKEYS.n);
    const e = cosePublicKey.get(COSEKEYS.e);

    if (!n) {
      throw new Error('COSE public key missing n (TPM|RSA)');
    }
    if (!e) {
      throw new Error('COSE public key missing e (TPM|RSA)');
    }

    if (!unique.equals(n as Buffer)) {
      throw new Error('PubArea unique is not same as credentialPublicKey (TPM|RSA)');
    }

    if (!parameters.rsa) {
      throw new Error(`Parsed pubArea type is RSA, but missing parameters.rsa (TPM|RSA)`);
    }

    const eBuffer = e as Buffer;
    // If `exponent` is equal to 0x00, then exponent is the default RSA exponent of 2^16+1 (65537)
    const pubAreaExponent = parameters.rsa.exponent || 65537;

    // Do some bit shifting to get to an integer
    const eSum = eBuffer[0] + (eBuffer[1] << 8) + (eBuffer[2] << 16);

    if (pubAreaExponent !== eSum) {
      throw new Error(`Unexpected public key exp ${eSum}, expected ${pubAreaExponent} (TPM|RSA)`);
    }
  } else if (pubType === 'TPM_ALG_ECC') {
    /**
     * TODO: Confirm this all works fine. Conformance tools v1.3.4 don't currently test ECC so I
     * had to eyeball it based on the **duo-labs/webauthn** library
     */
    const crv = cosePublicKey.get(COSEKEYS.crv);
    const x = cosePublicKey.get(COSEKEYS.x);
    const y = cosePublicKey.get(COSEKEYS.y);

    if (!crv) {
      throw new Error('COSE public key missing crv (TPM|ECC)');
    }
    if (!x) {
      throw new Error('COSE public key missing x (TPM|ECC)');
    }
    if (!y) {
      throw new Error('COSE public key missing y (TPM|ECC)');
    }

    if (!unique.equals(Buffer.concat([x as Buffer, y as Buffer]))) {
      throw new Error('PubArea unique is not same as public key x and y (TPM|ECC)');
    }

    if (!parameters.ecc) {
      throw new Error(`Parsed pubArea type is ECC, but missing parameters.ecc (TPM|ECC)`);
    }

    const pubAreaCurveID = parameters.ecc.curveID;
    const pubKeyCurveID = TPM_ECC_CURVE[(crv as Buffer).readUInt16BE(0)];
    if (pubAreaCurveID !== pubKeyCurveID) {
      throw new Error(
        `Unexpected public key curve ID "${pubKeyCurveID}", expected "${pubAreaCurveID}" (TPM|ECC)`,
      );
    }
  } else {
    throw new Error(`Unsupported pubArea.type "${pubType}"`);
  }

  const parsedCertInfo = parseCertInfo(certInfo);
  const { magic, type: certType, attested, extraData } = parsedCertInfo;

  if (magic !== 0xff544347) {
    throw new Error(`Unexpected magic value "${magic}", expected "0xff544347" (TPM)`);
  }

  if (certType !== 'TPM_ST_ATTEST_CERTIFY') {
    throw new Error(`Unexpected type "${certType}", expected "TPM_ST_ATTEST_CERTIFY" (TPM)`);
  }

  // Hash pubArea to create pubAreaHash using the nameAlg in attested
  const pubAreaHash = toHash(pubArea, attested.nameAlg.replace('TPM_ALG_', ''));

  // Concatenate attested.nameAlg and pubAreaHash to create attestedName.
  const attestedName = Buffer.concat([attested.nameAlgBuffer, pubAreaHash]);

  // Check that certInfo.attested.name is equals to attestedName.
  if (!attested.name.equals(attestedName)) {
    throw new Error(`Attested name comparison failed (TPM)`);
  }

  // Concatenate authData with clientDataHash to create attToBeSigned
  const attToBeSigned = Buffer.concat([authData, clientDataHash]);

  // Hash attToBeSigned using the algorithm specified in attStmt.alg to create attToBeSignedHash
  const hashAlg: string = COSEALGHASH[alg as number];
  const attToBeSignedHash = toHash(attToBeSigned, hashAlg);

  // Check that certInfo.extraData is equals to attToBeSignedHash.
  if (!extraData.equals(attToBeSignedHash)) {
    throw new Error('CertInfo extra data did not equal hashed attestation (TPM)');
  }

  /**
   * Verify signature
   */
  if (x5c.length < 1) {
    throw new Error('No certificates present in x5c array (TPM)');
  }

  // Pick a leaf AIK certificate of the x5c array and parse it.
  const leafCertPEM = convertASN1toPEM(x5c[0]);
  const leafCertInfo = getCertificateInfo(leafCertPEM);
  const { basicConstraintsCA, version, subject, notAfter, notBefore } = leafCertInfo;

  if (basicConstraintsCA) {
    throw new Error('Certificate basic constraints CA was not `false` (TPM)');
  }

  // Check that certificate is of version 3 (value must be set to 2).
  if (version !== 3) {
    throw new Error('Certificate version was not `3` (ASN.1 value of 2) (TPM)');
  }

  // Check that Subject sequence is empty.
  if (Object.keys(subject).length > 0) {
    throw new Error('Certificate subject was not empty (TPM)');
  }

  // Check that certificate is currently valid
  let now = new Date();
  if (notBefore > now) {
    throw new Error(`Certificate not good before "${notBefore.toString()}" (TPM)`);
  }

  // Check that certificate has not expired
  now = new Date();
  if (notAfter < now) {
    throw new Error(`Certificate not good after "${notAfter.toString()}" (TPM)`);
  }

  /**
   * Plumb the depths of the certificate's ASN.1-formatted data for some values we need to verify
   */
  const certASN1 = leafCertToASN1Object(x5c[0]);

  const tcgAtTpmManufacturer = getASN1TcgAtTpmManufacturer(certASN1);
  const tcgAtTpmModel = getASN1TcgAtTpmModel(certASN1);
  const tcgAtTpmVersion = getASN1TcgAtTpmVersion(certASN1);
  const extKeyUsage = getASN1ExtKeyUsage(certASN1);

  const parsedCert = AsnParser.parse(x5c[0], Certificate);

  if (!parsedCert.tbsCertificate.extensions) {
    throw new Error('Certificate was missing extensions (TPM)');
  }

  let subjectAltNamePresent: SubjectAlternativeName | undefined;
  parsedCert.tbsCertificate.extensions.forEach(ext => {
    if (ext.extnID === id_ce_subjectAltName) {
      subjectAltNamePresent = AsnParser.parse(ext.extnValue.slice(0), SubjectAlternativeName);
    }
  });

  // Check that certificate contains subjectAltName (2.5.29.17) extension,
  if (!subjectAltNamePresent) {
    throw new Error('Certificate did not contain subjectAltName extension (TPM)');
  }

  if (!tcgAtTpmManufacturer || !tcgAtTpmModel || !tcgAtTpmVersion) {
    throw new Error('Certificate contained incomplete subjectAltName data (TPM)');
  }

  // Check that tcpaTpmManufacturer (2.23.133.2.1) field is set to a valid manufacturer ID.
  if (!TPM_MANUFACTURERS[tcgAtTpmManufacturer]) {
    throw new Error(`Could not match TPM manufacturer "${tcgAtTpmManufacturer}" (TPM)`);
  }

  // Check that certificate contains extKeyUsage (2.5.29.37) extension and it must contain
  // tcg-kp-AIKCertificate (2.23.133.8.3) OID.
  if (extKeyUsage !== '2.23.133.8.3') {
    throw new Error(`Unexpected extKeyUsage "${extKeyUsage}", expected "2.23.133.8.3" (TPM)`);
  }

  // TODO: If certificate contains id-fido-gen-ce-aaguid(1.3.6.1.4.1.45724.1.1.4) extension, check
  // that it’s value is set to the same AAGUID as in authData.

  // Run some metadata checks if a statement exists for this authenticator
  const statement = await MetadataService.getStatement(aaguid);
  if (statement) {
    try {
      await verifyAttestationWithMetadata(statement, alg, x5c);
    } catch (err) {
      throw new Error(`${err.message} (TPM)`);
    }
  }

  // Verify signature over certInfo with the public key extracted from AIK certificate.
  // Get Martini friend, you are done!
  return verifySignature(sig, certInfo, leafCertPEM, hashAlg);
}

function getASN1TcgAtTpmManufacturer(certASN1: ASN1Object): string {
  const oid = '2.23.133.2.1';
  const ext = findOID(certASN1, oid);

  if (!ext) {
    return '';
  }

  /**
   * Return "id:FFFFF1D0" from the following data structure
   *
   * {
   *   "type": "SEQUENCE",
   *   "data": [
   *     {
   *       "type": "OBJECT_IDENTIFIER",
   *       "data": "2.23.133.2.1\ntcpaTpmManufacturer\nTCPA Attribute"
   *     },
   *     {
   *       "type": "UTF8String",
   *       "data": "id:FFFFF1D0"
   *     }
   *   ]
   * }
   */

  return (ext.data as JASN1[])[1].data as string;
}

function getASN1TcgAtTpmModel(certASN1: ASN1Object): string {
  const oid = '2.23.133.2.2';
  const ext = findOID(certASN1, oid);

  if (!ext) {
    return '';
  }

  /**
   * Return "NPCT6xx" from the following data structure
   *
   * {
   *   "type": "SEQUENCE",
   *   "data": [
   *     {
   *       "type": "OBJECT_IDENTIFIER",
   *       "data": "2.23.133.2.2\ntcpaTpmModel\nTCPA Attribute"
   *     },
   *     {
   *       "type": "UTF8String",
   *       "data": "NPCT6xx"
   *     }
   *   ]
   * }
   */

  return (ext.data as JASN1[])[1].data as string;
}

function getASN1TcgAtTpmVersion(certASN1: ASN1Object): string {
  const oid = '2.23.133.2.3';
  const ext = findOID(certASN1, oid);

  if (!ext) {
    return '';
  }

  /**
   * Return "id:13" from the following data structure:
   *
   * {
   *   "type": "SEQUENCE",
   *   "data": [
   *     {
   *       "type": "OBJECT_IDENTIFIER",
   *       "data": "2.23.133.2.3\ntcpaTpmVersion\nTCPA Attribute"
   *     },
   *     {
   *       "type": "UTF8String",
   *       "data": "id:13"
   *     }
   *   ]
   * }
   */

  return (ext.data as JASN1[])[1].data as string;
}

function getASN1ExtKeyUsage(certASN1: ASN1Object): string {
  const oid = '2.5.29.37';
  const ext = findOID(certASN1, oid);

  if (!ext) {
    return '';
  }

  /**
   * Return "2.23.133.8.3" from the following data structure:
   *
   * {
   *   "type": "SEQUENCE",
   *   "data": [
   *     {
   *       "type": "OBJECT_IDENTIFIER",
   *       "data": "2.5.29.37\nextKeyUsage\nX.509 extension"
   *     },
   *     {
   *       "type": "OCTET_STRING",
   *       "data": [
   *         {
   *           "type": "SEQUENCE",
   *           "data": [
   *             {
   *               "type": "OBJECT_IDENTIFIER",
   *               "data": "2.23.133.8.3"
   *             }
   *           ]
   *         }
   *       ]
   *     }
   *   ]
   * }
   */

  const root = ext.data as JASN1[];
  const root1 = root[1].data as JASN1[];
  const root2 = root1[0].data as JASN1[];
  const value = root2[0].data as string;

  return value;
}
