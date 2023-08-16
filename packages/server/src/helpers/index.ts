import { convertAAGUIDToString } from './convertAAGUIDToString.ts';
import { convertCertBufferToPEM } from './convertCertBufferToPEM.ts';
import { convertCOSEtoPKCS } from './convertCOSEtoPKCS.ts';
import { decodeAttestationObject } from './decodeAttestationObject.ts';
import { decodeClientDataJSON } from './decodeClientDataJSON.ts';
import { decodeCredentialPublicKey } from './decodeCredentialPublicKey.ts';
import { generateChallenge } from './generateChallenge.ts';
import { getCertificateInfo } from './getCertificateInfo.ts';
import { isCertRevoked } from './isCertRevoked.ts';
import { parseAuthenticatorData } from './parseAuthenticatorData.ts';
import { toHash } from './toHash.ts';
import { validateCertificatePath } from './validateCertificatePath.ts';
import { verifySignature } from './verifySignature.ts';
import { isoCBOR, isoBase64URL, isoUint8Array, isoCrypto } from './iso/index.ts';
import * as cose from './cose.ts';

export {
  convertAAGUIDToString,
  convertCertBufferToPEM,
  convertCOSEtoPKCS,
  decodeAttestationObject,
  decodeClientDataJSON,
  decodeCredentialPublicKey,
  generateChallenge,
  getCertificateInfo,
  isCertRevoked,
  parseAuthenticatorData,
  toHash,
  validateCertificatePath,
  verifySignature,
  isoCBOR,
  isoCrypto,
  isoBase64URL,
  isoUint8Array,
  cose,
};

import type {
  AttestationFormat,
  AttestationObject,
  AttestationStatement,
} from './decodeAttestationObject.ts';
import type { CertificateInfo } from './getCertificateInfo.ts';
import type { ClientDataJSON } from './decodeClientDataJSON.ts';
import type { COSEPublicKey } from './cose.ts';
import type { ParsedAuthenticatorData } from './parseAuthenticatorData.ts';

export type {
  AttestationFormat,
  AttestationObject,
  AttestationStatement,
  CertificateInfo,
  ClientDataJSON,
  COSEPublicKey,
  ParsedAuthenticatorData,
};
