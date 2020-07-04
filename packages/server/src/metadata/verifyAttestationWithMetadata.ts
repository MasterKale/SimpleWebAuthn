import { Base64URLString } from '@simplewebauthn/typescript-types';

import { MetadataStatement } from './metadataService';
import { FIDO_METADATA_AUTH_ALG_TO_COSE } from '../helpers/constants';
import convertASN1toPEM from '../helpers/convertASN1toPEM';
import validateCertificatePath from '../helpers/validateCertificatePath';

export default function verifyAttestationWithMetadata(
  statement: MetadataStatement,
  alg: number,
  x5c: Buffer[] | Base64URLString[],
): boolean {
  // Make sure the alg in the attestation statement matches the one specified in the metadata
  const metaCOSE = FIDO_METADATA_AUTH_ALG_TO_COSE[statement.authenticationAlgorithm];
  if (metaCOSE.alg !== alg) {
    throw new Error(`Attestation alg "${alg}" did not match metadata auth alg "${metaCOSE.alg}"`);
  }

  // Try to validate the chain with each metadata root cert until we find one that works
  let foundValidPath = false;
  for (const rootCert of statement.attestationRootCertificates) {
    try {
      const path = [...x5c, rootCert].map(convertASN1toPEM);
      foundValidPath = validateCertificatePath(path);
    } catch (err) {
      // Swallow the error for now
      foundValidPath = false;
    }

    // Don't continue if we've validated a full path
    if (foundValidPath) {
      break;
    }
  }

  if (!foundValidPath) {
    throw new Error(`Could not validate certificate path with any metadata root certificates`);
  }

  return true;
}
