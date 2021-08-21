import { Base64URLString } from '@simplewebauthn/typescript-types';

import { MetadataStatement } from '../metadata/mdsTypes';
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

type COSEInfo = {
  kty: number;
  alg: number;
  crv?: number;
};

/**
 * Convert ALG_SIGN values to COSE info
 * https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#authentication-algorithms
 */
function algSignToCOSEInfo(algSign: AlgSign): COSEInfo | undefined {
  switch (algSign) {
    case 'secp256r1_ecdsa_sha256_raw':
    case 'secp256r1_ecdsa_sha256_der':
      return { kty: 2, alg: -7, crv: 1 };
    case 'rsassa_pss_sha256_raw':
    case 'rsassa_pss_sha256_der':
      return { kty: 3, alg: -37 };
    case 'secp256k1_ecdsa_sha256_raw':
    case 'secp256k1_ecdsa_sha256_der':
      return { kty: 2, alg: -7, crv: 8 };
    case 'rsassa_pss_sha384_raw':
      return { kty: 3, alg: -38 };
    case 'rsassa_pkcsv15_sha256_raw':
      return { kty: 3, alg: -257 };
    case 'rsassa_pkcsv15_sha384_raw':
      return { kty: 3, alg: -258 };
    case 'rsassa_pkcsv15_sha512_raw':
      return { kty: 3, alg: -259 };
    case 'rsassa_pkcsv15_sha1_raw':
      return { kty: 3, alg: -65535 };
    case 'secp384r1_ecdsa_sha384_raw':
      return { kty: 2, alg: -35, crv: 2 };
    case 'secp512r1_ecdsa_sha256_raw':
      return { kty: 2, alg: -36, crv: 3 };
    case 'ed25519_eddsa_sha512_raw':
      return { kty: 1, alg: -8, crv: 6 };
    // TODO: COSE info in FIDO Registry v2.1 isn't readily available for these, these seem rare...
    // case 'sm2_sm3_raw':
    //   return {};
    // case 'rsa_emsa_pkcs1_sha256_raw':
    // case 'rsa_emsa_pkcs1_sha256_der':
    //   return {};
    default:
      return undefined;
  }
}
