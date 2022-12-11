import { convertAAGUIDToString } from './convertAAGUIDToString';
import { convertCertBufferToPEM } from './convertCertBufferToPEM';
import { convertCOSEtoPKCS } from './convertCOSEtoPKCS';
import { decodeAttestationObject } from './decodeAttestationObject';
import { decodeClientDataJSON } from './decodeClientDataJSON';
import { decodeCredentialPublicKey } from './decodeCredentialPublicKey';
import { generateChallenge } from './generateChallenge';
import { getCertificateInfo } from './getCertificateInfo';
import { isCertRevoked } from './isCertRevoked';
import { parseAuthenticatorData } from './parseAuthenticatorData';
import { toHash } from './toHash';
import { validateCertificatePath } from './validateCertificatePath';
import { verifySignature } from './verifySignature';
import { isoCBOR, isoBase64URL, isoUint8Array, isoCrypto } from './iso';
import * as cose from './cose';

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
} from './decodeAttestationObject';
import type { CertificateInfo } from './getCertificateInfo';
import type { ClientDataJSON } from './decodeClientDataJSON';
import type { COSEPublicKey } from './cose';
import type { ParsedAuthenticatorData } from './parseAuthenticatorData';

export type {
  AttestationFormat,
  AttestationObject,
  AttestationStatement,
  CertificateInfo,
  ClientDataJSON,
  COSEPublicKey,
  ParsedAuthenticatorData,
};
