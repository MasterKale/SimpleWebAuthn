import type { AttestationStatement } from '../../../helpers/decodeAttestationObject';

import parseCertInfo from './parseCertInfo';
import parsePubArea from './parsePubArea';

type Options = {
  aaguid: Buffer;
  attStmt: AttestationStatement;
};

export default function verifyTPM(options: Options): boolean {
  const { aaguid, attStmt, decodedPublicKey } = options;
  const { ver, alg, x5c, pubArea, certInfo } = attStmt;

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

  const parsedPubArea = parsePubArea(pubArea);
  console.log(parsedPubArea);

  const parsedCertInfo = parseCertInfo(certInfo);
  console.log(parsedCertInfo);
  const { magic, type } = parsedCertInfo;

  if (magic !== 4283712327) {
    throw new Error(`Unexpected magic value "${magic}", expected "4283712327" (TPM)`);
  }

  if (type !== 'TPM_ST_ATTEST_CERTIFY') {
    throw new Error(`Unexpected type "${type}", expected "TPM_ST_ATTEST_CERTIFY" (TPM)`);
  }

  throw new Error(`Format "tpm" not yet supported`);
}
