import { Base64URLString } from '@simplewebauthn/typescript-types';

import { MetadataStatement } from '../services/metadataService';
import { FIDO_METADATA_AUTH_ALG_TO_COSE } from '../helpers/constants';
import convertCertBufferToPEM from '../helpers/convertCertBufferToPEM';
import validateCertificatePath from '../helpers/validateCertificatePath';

export default async function verifyAttestationWithMetadata(
  statement: MetadataStatement,
  alg: number,
  x5c: Buffer[] | Base64URLString[],
): Promise<boolean> {
  // Make sure the alg in the attestation statement matches the one specified in the metadata
  const metaCOSE = FIDO_METADATA_AUTH_ALG_TO_COSE[statement.authenticationAlgorithm];
  if (metaCOSE.alg !== alg) {
    throw new Error(`Attestation alg "${alg}" did not match metadata auth alg "${metaCOSE.alg}"`);
  }

  try {
    await validateCertificatePath(
      x5c.map(convertCertBufferToPEM),
      statement.attestationRootCertificates.map(convertCertBufferToPEM),
    );
  } catch (err) {
    throw new Error(`Could not validate certificate path with any metadata root certificates`);
  }

  return true;
}
