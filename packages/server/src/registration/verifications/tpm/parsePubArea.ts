import { TPM_ALG, TPM_ECC_CURVE } from './constants';

/**
 * Break apart a TPM attestation's pubArea buffer
 *
 * See 12.2.4 TPMT_PUBLIC here:
 * https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-00.96-130315.pdf
 */
export function parsePubArea(pubArea: Buffer): ParsedPubArea {
  let pointer = 0;

  const typeBuffer = pubArea.slice(pointer, (pointer += 2));
  const type = TPM_ALG[typeBuffer.readUInt16BE(0)];

  const nameAlgBuffer = pubArea.slice(pointer, (pointer += 2));
  const nameAlg = TPM_ALG[nameAlgBuffer.readUInt16BE(0)];

  // Get some authenticator attributes(?)
  const objectAttributesInt = pubArea.slice(pointer, (pointer += 4)).readUInt32BE(0);
  const objectAttributes = {
    fixedTPM: !!(objectAttributesInt & 1),
    stClear: !!(objectAttributesInt & 2),
    fixedParent: !!(objectAttributesInt & 8),
    sensitiveDataOrigin: !!(objectAttributesInt & 16),
    userWithAuth: !!(objectAttributesInt & 32),
    adminWithPolicy: !!(objectAttributesInt & 64),
    noDA: !!(objectAttributesInt & 512),
    encryptedDuplication: !!(objectAttributesInt & 1024),
    restricted: !!(objectAttributesInt & 32768),
    decrypt: !!(objectAttributesInt & 65536),
    signOrEncrypt: !!(objectAttributesInt & 131072),
  };

  // Slice out the authPolicy of dynamic length
  const authPolicyLength = pubArea.slice(pointer, (pointer += 2)).readUInt16BE(0);
  const authPolicy = pubArea.slice(pointer, (pointer += authPolicyLength));

  // Extract additional curve params according to type
  const parameters: { rsa?: RSAParameters; ecc?: ECCParameters } = {};
  let unique = Buffer.from([]);

  if (type === 'TPM_ALG_RSA') {
    const rsaBuffer = pubArea.slice(pointer, (pointer += 10));

    parameters.rsa = {
      symmetric: TPM_ALG[rsaBuffer.slice(0, 2).readUInt16BE(0)],
      scheme: TPM_ALG[rsaBuffer.slice(2, 4).readUInt16BE(0)],
      keyBits: rsaBuffer.slice(4, 6).readUInt16BE(0),
      exponent: rsaBuffer.slice(6, 10).readUInt32BE(0),
    };

    /**
     * See 11.2.4.5 TPM2B_PUBLIC_KEY_RSA here:
     * https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-00.96-130315.pdf
     */
    const uniqueLength = pubArea.slice(pointer, (pointer += 2)).readUInt16BE(0);

    unique = pubArea.slice(pointer, (pointer += uniqueLength));
  } else if (type === 'TPM_ALG_ECC') {
    const eccBuffer = pubArea.slice(pointer, (pointer += 8));

    parameters.ecc = {
      symmetric: TPM_ALG[eccBuffer.slice(0, 2).readUInt16BE(0)],
      scheme: TPM_ALG[eccBuffer.slice(2, 4).readUInt16BE(0)],
      curveID: TPM_ECC_CURVE[eccBuffer.slice(4, 6).readUInt16BE(0)],
      kdf: TPM_ALG[eccBuffer.slice(6, 8).readUInt16BE(0)],
    };

    /**
     * See 11.2.5.1 TPM2B_ECC_PARAMETER here:
     * https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-00.96-130315.pdf
     */
    // Retrieve X
    const uniqueXLength = pubArea.slice(pointer, (pointer += 2)).readUInt16BE(0);
    const uniqueX = pubArea.slice(pointer, (pointer += uniqueXLength));
    // Retrieve Y
    const uniqueYLength = pubArea.slice(pointer, (pointer += 2)).readUInt16BE(0);
    const uniqueY = pubArea.slice(pointer, (pointer += uniqueYLength));

    unique = Buffer.concat([uniqueX, uniqueY]);
  } else {
    throw new Error(`Unexpected type "${type}" (TPM)`);
  }

  return {
    type,
    nameAlg,
    objectAttributes,
    authPolicy,
    parameters,
    unique,
  };
}

type ParsedPubArea = {
  type: 'TPM_ALG_RSA' | 'TPM_ALG_ECC';
  nameAlg: string;
  objectAttributes: {
    fixedTPM: boolean;
    stClear: boolean;
    fixedParent: boolean;
    sensitiveDataOrigin: boolean;
    userWithAuth: boolean;
    adminWithPolicy: boolean;
    noDA: boolean;
    encryptedDuplication: boolean;
    restricted: boolean;
    decrypt: boolean;
    signOrEncrypt: boolean;
  };
  authPolicy: Buffer;
  parameters: {
    rsa?: RSAParameters;
    ecc?: ECCParameters;
  };
  unique: Buffer;
};

type RSAParameters = {
  symmetric: string;
  scheme: string;
  keyBits: number;
  exponent: number;
};

type ECCParameters = {
  symmetric: string;
  scheme: string;
  curveID: string;
  kdf: string;
};
