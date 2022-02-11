import { Base64URLString } from '@simplewebauthn/typescript-types';

import { MetadataStatement, AlgSign } from '../metadata/mdsTypes';
import convertCertBufferToPEM from '../helpers/convertCertBufferToPEM';
import validateCertificatePath from '../helpers/validateCertificatePath';
import decodeCredentialPublicKey from '../helpers/decodeCredentialPublicKey';
import { COSEKEYS, COSEKTY } from '../helpers/convertCOSEtoPKCS';

/**
 * Match properties of the authenticator's attestation statement against expected values as
 * registered with the FIDO Alliance Metadata Service
 */
export default async function verifyAttestationWithMetadata(
  statement: MetadataStatement,
  credentialPublicKey: Buffer,
  x5c: Buffer[] | Base64URLString[],
): Promise<boolean> {
  // Make sure the alg in the attestation statement matches one of the ones specified in metadata
  const keypairCOSEAlgs: Set<COSEInfo> = new Set();
  statement.authenticationAlgorithms.forEach(algSign => {
    // Convert algSign string to { kty, alg, crv }
    const algSignCOSEINFO = algSignToCOSEInfo(algSign);

    if (algSignCOSEINFO) {
      keypairCOSEAlgs.add(algSignCOSEINFO);
    }
  });

  // Extract the public key's COSE info for comparison
  const decodedPublicKey = decodeCredentialPublicKey(credentialPublicKey);
  // Assume everything is a number because these values should be
  const publicKeyCOSEInfo: COSEInfo = {
    kty: decodedPublicKey.get(COSEKEYS.kty) as number,
    alg: decodedPublicKey.get(COSEKEYS.alg) as number,
    crv: decodedPublicKey.get(COSEKEYS.crv) as number,
  };
  if (!publicKeyCOSEInfo.crv) {
    delete publicKeyCOSEInfo.crv;
  }

  /**
   * Attempt to match the credential public key's algorithm to one specified in the device's
   * metadata
   */
  let foundMatch = false;
  for (const keypairAlg of keypairCOSEAlgs) {
    // Make sure algorithm and key type match
    if (keypairAlg.alg === publicKeyCOSEInfo.alg && keypairAlg.kty === publicKeyCOSEInfo.kty) {
      // If not an RSA keypair then make sure curve numbers match too
      if (
        (keypairAlg.kty === COSEKTY.EC2 || keypairAlg.kty === COSEKTY.OKP)
        && keypairAlg.crv === publicKeyCOSEInfo.crv
      ) {
        foundMatch = true;
      } else {
        // We've matched an RSA public key's properties
        foundMatch = true;
      }
    }

    if (foundMatch) {
      break;
    }
  }

  // Make sure the public key is one of the allowed algorithms
  if (!foundMatch) {
    const debugAlgs = Array.from(keypairCOSEAlgs).join(', ');
    throw new Error(`Public key algorithm ${publicKeyCOSEInfo} did not match any metadata algorithms [${debugAlgs}]`);
  }

  try {
    await validateCertificatePath(
      x5c.map(convertCertBufferToPEM),
      statement.attestationRootCertificates.map(convertCertBufferToPEM),
    );
  } catch (err) {
    throw new Error(`Could not validate certificate path with any metadata root certificates: ${err.message}`);
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
