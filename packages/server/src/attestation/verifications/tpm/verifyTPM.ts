import type { AttestationStatement } from '../../../helpers/decodeAttestationObject';
import decodeCredentialPublicKey from '../../../helpers/decodeCredentialPublicKey';
import convertAAGUIDToString from '../../../helpers/convertAAGUIDToString';
import { COSEKEYS } from '../../../helpers/convertCOSEtoPKCS';

import parseCertInfo from './parseCertInfo';
import parsePubArea from './parsePubArea';

type Options = {
  aaguid: Buffer;
  attStmt: AttestationStatement;
  authData: Buffer;
  credentialPublicKey: Buffer;
};

export default function verifyTPM(options: Options): boolean {
  const { aaguid, attStmt, authData, credentialPublicKey } = options;
  const { ver, alg, x5c, pubArea, certInfo } = attStmt;

  /**
   * Verify structures
   */
  if (ver !== '2.0') {
    throw new Error(`Unexpected ver "${ver}", expected "2.0" (TPM)`);
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
  console.log(parsedPubArea);
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
    throw new Error(`Unsupported pubArea.type "${pubType}"`);
  } else {
    throw new Error(`Unsupported pubArea.type "${pubType}"`);
  }

  const parsedCertInfo = parseCertInfo(certInfo);
  console.log({ parsedCertInfo });
  const { magic, type: certType, attested } = parsedCertInfo;

  if (magic !== 4283712327) {
    throw new Error(`Unexpected magic value "${magic}", expected "4283712327" (TPM)`);
  }

  if (certType !== 'TPM_ST_ATTEST_CERTIFY') {
    throw new Error(`Unexpected type "${certType}", expected "TPM_ST_ATTEST_CERTIFY" (TPM)`);
  }

  // TODO: Hash pubArea to create pubAreaHash using the nameAlg in attested

  // TODO: Concatenate attested.nameAlg and pubAreaHash to create attestedName.

  // TODO: Check that certInfo.attested.name is equals to attestedName.

  // TODO: Concatenate authData with clientDataHash to create attToBeSigned

  // TODO: Hash attToBeSigned using the algorithm specified in attStmt.alg to create
  // attToBeSignedHash

  // TODO: Check that certInfo.extraData is equals to attToBeSignedHash.

  /**
   * Verify signature
   */
  // TODO: Pick a leaf AIK certificate of the x5c array and parse it.

  // TODO: Check that certificate if of version 3(value must be set to 2).

  // TODO: Check that Subject sequence is empty.

  // TODO: Check that certificate is not expired and is started.

  // TODO: Check that certificate contains subjectAltName(2.5.29.17) extension, and check that
  // tcpaTpmManufacturer(2.23.133.2.1) field is set to the existing manufacturer ID. You can find
  // list of TPM_MANUFACTURERS in the appendix.

  // TODO: Check that certificate contains extKeyUsage(2.5.29.37) extension and it must contain
  // tcg-kp-AIKCertificate (2.23.133.8.3) OID.

  // TODO: If certificate contains id-fido-gen-ce-aaguid(1.3.6.1.4.1.45724.1.1.4) extension, check
  // that it’s value is set to the same AAGUID as in authData.

  // TODO: For attestationRoot in metadata.attestationRootCertificates, generate verification chain
  // verifX5C by appending attestationRoot to the x5c. Try verifying verifX5C. If successful go to
  // next step. If fail try next attestationRoot. If no attestationRoots left to try, fail.

  // TODO: Verify signature over certInfo with the public key extracted from AIK certificate.

  // TODO: Get Martini friend, you are done!

  throw new Error(`Format "tpm" not yet supported`);
}
