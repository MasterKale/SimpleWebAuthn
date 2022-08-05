/* eslint-disable @typescript-eslint/ban-ts-comment */
export const TPM_ST: { [key: number]: string } = {
  0x00c4: 'TPM_ST_RSP_COMMAND',
  0x8000: 'TPM_ST_NULL',
  0x8001: 'TPM_ST_NO_SESSIONS',
  0x8002: 'TPM_ST_SESSIONS',
  0x8014: 'TPM_ST_ATTEST_NV',
  0x8015: 'TPM_ST_ATTEST_COMMAND_AUDIT',
  0x8016: 'TPM_ST_ATTEST_SESSION_AUDIT',
  0x8017: 'TPM_ST_ATTEST_CERTIFY',
  0x8018: 'TPM_ST_ATTEST_QUOTE',
  0x8019: 'TPM_ST_ATTEST_TIME',
  0x801a: 'TPM_ST_ATTEST_CREATION',
  0x8021: 'TPM_ST_CREATION',
  0x8022: 'TPM_ST_VERIFIED',
  0x8023: 'TPM_ST_AUTH_SECRET',
  0x8024: 'TPM_ST_HASHCHECK',
  0x8025: 'TPM_ST_AUTH_SIGNED',
  0x8029: 'TPM_ST_FU_MANIFEST',
};

export const TPM_ALG: { [key: number]: string } = {
  0x0000: 'TPM_ALG_ERROR',
  0x0001: 'TPM_ALG_RSA',
  0x0004: 'TPM_ALG_SHA',
  // @ts-ignore 2300
  0x0004: 'TPM_ALG_SHA1',
  0x0005: 'TPM_ALG_HMAC',
  0x0006: 'TPM_ALG_AES',
  0x0007: 'TPM_ALG_MGF1',
  0x0008: 'TPM_ALG_KEYEDHASH',
  0x000a: 'TPM_ALG_XOR',
  0x000b: 'TPM_ALG_SHA256',
  0x000c: 'TPM_ALG_SHA384',
  0x000d: 'TPM_ALG_SHA512',
  0x0010: 'TPM_ALG_NULL',
  0x0012: 'TPM_ALG_SM3_256',
  0x0013: 'TPM_ALG_SM4',
  0x0014: 'TPM_ALG_RSASSA',
  0x0015: 'TPM_ALG_RSAES',
  0x0016: 'TPM_ALG_RSAPSS',
  0x0017: 'TPM_ALG_OAEP',
  0x0018: 'TPM_ALG_ECDSA',
  0x0019: 'TPM_ALG_ECDH',
  0x001a: 'TPM_ALG_ECDAA',
  0x001b: 'TPM_ALG_SM2',
  0x001c: 'TPM_ALG_ECSCHNORR',
  0x001d: 'TPM_ALG_ECMQV',
  0x0020: 'TPM_ALG_KDF1_SP800_56A',
  0x0021: 'TPM_ALG_KDF2',
  0x0022: 'TPM_ALG_KDF1_SP800_108',
  0x0023: 'TPM_ALG_ECC',
  0x0025: 'TPM_ALG_SYMCIPHER',
  0x0026: 'TPM_ALG_CAMELLIA',
  0x0040: 'TPM_ALG_CTR',
  0x0041: 'TPM_ALG_OFB',
  0x0042: 'TPM_ALG_CBC',
  0x0043: 'TPM_ALG_CFB',
  0x0044: 'TPM_ALG_ECB',
};

export const TPM_ECC_CURVE: { [key: number]: string } = {
  0x0000: 'TPM_ECC_NONE',
  0x0001: 'TPM_ECC_NIST_P192',
  0x0002: 'TPM_ECC_NIST_P224',
  0x0003: 'TPM_ECC_NIST_P256',
  0x0004: 'TPM_ECC_NIST_P384',
  0x0005: 'TPM_ECC_NIST_P521',
  0x0010: 'TPM_ECC_BN_P256',
  0x0011: 'TPM_ECC_BN_P638',
  0x0020: 'TPM_ECC_SM2_P256',
};

type ManufacturerInfo = {
  name: string;
  id: string;
};

export const TPM_MANUFACTURERS: { [key: string]: ManufacturerInfo } = {
  'id:414D4400': {
    name: 'AMD',
    id: 'AMD',
  },
  'id:41544D4C': {
    name: 'Atmel',
    id: 'ATML',
  },
  'id:4252434D': {
    name: 'Broadcom',
    id: 'BRCM',
  },
  'id:49424d00': {
    name: 'IBM',
    id: 'IBM',
  },
  'id:49465800': {
    name: 'Infineon',
    id: 'IFX',
  },
  'id:494E5443': {
    name: 'Intel',
    id: 'INTC',
  },
  'id:4C454E00': {
    name: 'Lenovo',
    id: 'LEN',
  },
  'id:4E534D20': {
    name: 'National Semiconductor',
    id: 'NSM',
  },
  'id:4E545A00': {
    name: 'Nationz',
    id: 'NTZ',
  },
  'id:4E544300': {
    name: 'Nuvoton Technology',
    id: 'NTC',
  },
  'id:51434F4D': {
    name: 'Qualcomm',
    id: 'QCOM',
  },
  'id:534D5343': {
    name: 'SMSC',
    id: 'SMSC',
  },
  'id:53544D20': {
    name: 'ST Microelectronics',
    id: 'STM',
  },
  'id:534D534E': {
    name: 'Samsung',
    id: 'SMSN',
  },
  'id:534E5300': {
    name: 'Sinosun',
    id: 'SNS',
  },
  'id:54584E00': {
    name: 'Texas Instruments',
    id: 'TXN',
  },
  'id:57454300': {
    name: 'Winbond',
    id: 'WEC',
  },
  'id:524F4343': {
    name: 'Fuzhouk Rockchip',
    id: 'ROCC',
  },
  'id:FFFFF1D0': {
    name: 'FIDO Alliance',
    id: 'FIDO',
  },
};

/**
 * Match TPM public area curve ID's to `crv` numbers used in COSE public keys
 */
export const TPM_ECC_CURVE_COSE_CRV_MAP: { [key: string]: number } = {
  TPM_ECC_NIST_P256: 1, // p256
  TPM_ECC_NIST_P384: 2, // p384
  TPM_ECC_NIST_P521: 3, // p521
  TPM_ECC_BN_P256: 1,   // p256
  TPM_ECC_SM2_P256: 1,  // p256
};
