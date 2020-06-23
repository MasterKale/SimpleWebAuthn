import type { AttestationStatement } from '../../../helpers/decodeAttestationObject';
import decodeCredentialPublicKey from '../../../helpers/decodeCredentialPublicKey';
import convertAAGUIDToString from '../../../helpers/convertAAGUIDToString';
import { COSEKEYS, COSEALGHASH } from '../../../helpers/convertCOSEtoPKCS';
import toHash from '../../../helpers/toHash';
import convertASN1toPEM from '../../../helpers/convertASN1toPEM';
import getCertificateInfo from '../../../helpers/getCertificateInfo';
import verifySignature from '../../../helpers/verifySignature';

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

export default function verifyTPM(options: Options): boolean {
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

  // TODO: Check that the “alg” field is set to the equivalent value to the signatureAlgorithm in
  // the metadata. You can find useful conversion tables in the appendix.
  console.log('aaguid:', convertAAGUIDToString(aaguid));

  const parsedPubArea = parsePubArea(pubArea);
  // console.log(parsedPubArea);
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
  // console.log({ parsedCertInfo });
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
  // console.log(leafCertPEM);
  const leafCertInfo = getCertificateInfo(leafCertPEM, 'tpm');
  const { basicConstraintsCA, version, subject, notAfter, notBefore, tpmInfo } = leafCertInfo;
  // console.log(leafCertInfo);

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

  if (!tpmInfo) {
    throw new Error(`No tpmInfo in leaf certificate info (TPM)`);
  }

  const {
    subjectAltNamePresent,
    tcgAtTpmManufacturer,
    tcgAtTpmModel,
    tcgAtTpmVersion,
    extKeyUsage,
  } = tpmInfo;

  // Check that certificate contains subjectAltName(2.5.29.17) extension,
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

  // TODO: For attestationRoot in metadata.attestationRootCertificates, generate verification chain
  // verifyX5C by appending attestationRoot to the x5c. Try verifying verifyX5C. If successful go to
  // next step. If fail try next attestationRoot. If no attestationRoots left to try, fail.
  // const verifyX5C =

  // Verify signature over certInfo with the public key extracted from AIK certificate.
  // Get Martini friend, you are done!
  return verifySignature(sig, certInfo, leafCertPEM, hashAlg);
}
