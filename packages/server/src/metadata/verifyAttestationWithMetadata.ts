import { Base64URLString } from '@simplewebauthn/typescript-types';

import type { MetadataStatement, AlgSign } from '../metadata/mdsTypes';
import { convertCertBufferToPEM } from '../helpers/convertCertBufferToPEM';
import { validateCertificatePath } from '../helpers/validateCertificatePath';
import { decodeCredentialPublicKey } from '../helpers/decodeCredentialPublicKey';
import { COSEKEYS, COSEKTY } from '../helpers/convertCOSEtoPKCS';

/**
 * Match properties of the authenticator's attestation statement against expected values as
 * registered with the FIDO Alliance Metadata Service
 */
export async function verifyAttestationWithMetadata(
  statement: MetadataStatement,
  credentialPublicKey: Buffer,
  x5c: Buffer[] | Base64URLString[],
): Promise<boolean> {
  // Make sure the alg in the attestation statement matches one of the ones specified in metadata
  const keypairCOSEAlgs: Set<COSEInfo> = new Set();
  statement.authenticationAlgorithms.forEach(algSign => {
    // Map algSign string to { kty, alg, crv }
    const algSignCOSEINFO = algSignToCOSEInfoMap[algSign];

    // Keeping this statement here just in case MDS returns something unexpected
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
        (keypairAlg.kty === COSEKTY.EC2 || keypairAlg.kty === COSEKTY.OKP) &&
        keypairAlg.crv === publicKeyCOSEInfo.crv
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
    const debugMDSAlgs = Array.from(keypairCOSEAlgs);
    // Construct some useful error output about the public key
    const debugPubKeyAlgInfo: COSEInfo = {
      kty: publicKeyCOSEInfo.kty,
      alg: publicKeyCOSEInfo.alg,
    };
    // Don't output a bunch of bytes for `crv` when the public key is an RSA key
    if (publicKeyCOSEInfo.kty !== COSEKTY.RSA) {
      debugPubKeyAlgInfo.crv = publicKeyCOSEInfo.crv;
    }

    const strPubKeyAlg = JSON.stringify(debugPubKeyAlgInfo);
    const strMDSAlgs = JSON.stringify(debugMDSAlgs);

    throw new Error(
      `Public key algorithm ${strPubKeyAlg} did not match any metadata algorithms ${strMDSAlgs}`,
    );
  }

  try {
    await validateCertificatePath(
      x5c.map(convertCertBufferToPEM),
      statement.attestationRootCertificates.map(convertCertBufferToPEM),
    );
  } catch (err) {
    const _err = err as Error;
    throw new Error(
      `Could not validate certificate path with any metadata root certificates: ${_err.message}`,
    );
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
 *
 * Values pulled from `ALG_KEY_COSE` definitions in the FIDO Registry of Predefined Values
 *
 * https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#authentication-algorithms
 */
export const algSignToCOSEInfoMap: { [key in AlgSign]: COSEInfo } = {
  secp256r1_ecdsa_sha256_raw: { kty: 2, alg: -7, crv: 1 },
  secp256r1_ecdsa_sha256_der: { kty: 2, alg: -7, crv: 1 },
  rsassa_pss_sha256_raw: { kty: 3, alg: -37 },
  rsassa_pss_sha256_der: { kty: 3, alg: -37 },
  secp256k1_ecdsa_sha256_raw: { kty: 2, alg: -47, crv: 8 },
  secp256k1_ecdsa_sha256_der: { kty: 2, alg: -47, crv: 8 },
  rsassa_pss_sha384_raw: { kty: 3, alg: -38 },
  rsassa_pkcsv15_sha256_raw: { kty: 3, alg: -257 },
  rsassa_pkcsv15_sha384_raw: { kty: 3, alg: -258 },
  rsassa_pkcsv15_sha512_raw: { kty: 3, alg: -259 },
  rsassa_pkcsv15_sha1_raw: { kty: 3, alg: -65535 },
  secp384r1_ecdsa_sha384_raw: { kty: 2, alg: -35, crv: 2 },
  secp512r1_ecdsa_sha256_raw: { kty: 2, alg: -36, crv: 3 },
  ed25519_eddsa_sha512_raw: { kty: 1, alg: -8, crv: 6 },
};
