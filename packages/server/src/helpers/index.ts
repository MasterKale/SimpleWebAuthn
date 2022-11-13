import { convertAAGUIDToString } from './convertAAGUIDToString';
import { convertCertBufferToPEM } from './convertCertBufferToPEM';
import { convertCOSEtoPKCS } from './convertCOSEtoPKCS';
import { convertPublicKeyToPEM } from './convertPublicKeyToPEM';
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
import { isoCBOR, isoBase64URL, isoUint8Array } from './iso';

export {
  convertAAGUIDToString,
  convertCertBufferToPEM,
  convertCOSEtoPKCS,
  convertPublicKeyToPEM,
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
  isoBase64URL,
  isoUint8Array,
};

import type {
  AttestationFormat,
  AttestationObject,
  AttestationStatement,
} from './decodeAttestationObject';
import type { CertificateInfo } from './getCertificateInfo';
import type { ClientDataJSON } from './decodeClientDataJSON';
import type { COSEPublicKey } from './convertCOSEtoPKCS';
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
