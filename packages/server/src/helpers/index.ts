import convertAAGUIDToString from './convertAAGUIDToString';
import convertCertBufferToPEM from './convertCertBufferToPEM';
import convertCOSEtoPKCS from './convertCOSEtoPKCS';
import convertPublicKeyToPEM from './convertPublicKeyToPEM';
import decodeAttestationObject from './decodeAttestationObject';
import { decodeCborFirst } from './decodeCbor';
import decodeClientDataJSON from './decodeClientDataJSON';
import decodeCredentialPublicKey from './decodeCredentialPublicKey';
import generateChallenge from './generateChallenge';
import getCertificateInfo from './getCertificateInfo';
import isBase64URLString from './isBase64URLString';
import isCertRevoked from './isCertRevoked';
import parseAuthenticatorData from './parseAuthenticatorData';
import toHash from './toHash';
import validateCertificatePath from './validateCertificatePath';
import verifySignature from './verifySignature';

export {
  convertAAGUIDToString,
  convertCertBufferToPEM,
  convertCOSEtoPKCS,
  convertPublicKeyToPEM,
  decodeAttestationObject,
  decodeCborFirst,
  decodeClientDataJSON,
  decodeCredentialPublicKey,
  generateChallenge,
  getCertificateInfo,
  isBase64URLString,
  isCertRevoked,
  parseAuthenticatorData,
  toHash,
  validateCertificatePath,
  verifySignature,
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
