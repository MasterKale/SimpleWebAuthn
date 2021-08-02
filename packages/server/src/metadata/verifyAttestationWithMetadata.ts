import { Base64URLString } from '@simplewebauthn/typescript-types';

import { MetadataStatement } from '../services/metadataService';
import { FIDO_METADATA_AUTH_ALG_TO_COSE } from '../helpers/constants';
import convertX509CertToPEM from '../helpers/convertX509CertToPEM';
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

  // Make a copy of x5c so we don't modify the original
  const path = [...x5c].map(convertX509CertToPEM);

  // Try to validate the chain with each metadata root cert until we find one that works
  let foundValidPath = false;
  for (const rootCert of statement.attestationRootCertificates) {
    try {
      // Push the root cert to the cert path and try to validate it
      path.push(convertX509CertToPEM(rootCert));
      foundValidPath = await validateCertificatePath(path);
    } catch (err) {
      // Swallow the error for now
      foundValidPath = false;
      // Remove the root cert before we try again with another
      path.splice(path.length - 1, 1);
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
