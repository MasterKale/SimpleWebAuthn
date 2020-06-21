import type { AttestationStatement } from '../../../helpers/decodeAttestationObject';

import parseCertInfo from './parseCertInfo';
import parsePubArea from './parsePubArea';

type Options = {
  aaguid: Buffer;
  attStmt: AttestationStatement;
};

export default function verifyTPM(options: Options): boolean {
  const { aaguid, attStmt } = options;
  const { ver, alg, pubArea, certInfo } = attStmt;

  if (ver !== '2.0') {
    throw new Error(`Unexpected ver "${ver}", expected "2.0"`);
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

  throw new Error(`Format "tpm" not yet supported`);
}
