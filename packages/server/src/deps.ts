// @simplewebauthn/typescript-types
export type {
  AuthenticationExtensionsClientInputs,
  PublicKeyCredentialRequestOptionsJSON,
  PublicKeyCredentialDescriptorFuture,
  UserVerificationRequirement,
  AuthenticationResponseJSON,
  AuthenticatorDevice,
  CredentialDeviceType,
  Base64URLString,
  AttestationConveyancePreference,
  AuthenticatorSelectionCriteria,
  COSEAlgorithmIdentifier,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialParameters,
  RegistrationResponseJSON,
} from '../../typescript-types/src/index.ts';

// @simplewebauthn/iso-webcrypto
export { default as WebCrypto } from '../../iso-webcrypto/src/browser.ts';

// cbor (a.k.a. cbor-x in Node land)
export * as cborx from 'https://deno.land/x/cbor@v1.5.2/index.js';

// NPM: cross-fetch
export { default as fetch } from 'npm:cross-fetch';

// NPM: debug
export { default as debug, Debugger } from 'npm:debug';

// NPM: @peculiar libraries
export { AsnParser, AsnSerializer } from 'npm:@peculiar/asn1-schema@^2.3.3';
export {
  AuthorityKeyIdentifier,
  BasicConstraints,
  Certificate,
  CertificateList,
  CRLDistributionPoints,
  ExtendedKeyUsage,
  id_ce_authorityKeyIdentifier,
  id_ce_basicConstraints,
  id_ce_cRLDistributionPoints,
  id_ce_extKeyUsage,
  id_ce_subjectAltName,
  id_ce_subjectKeyIdentifier,
  Name,
  SubjectAlternativeName,
  SubjectKeyIdentifier,
} from 'npm:@peculiar/asn1-x509@^2.3.4';
export {
  ECDSASigValue,
  ECParameters,
  id_ecPublicKey,
  id_secp256r1,
  id_secp384r1,
} from 'npm:@peculiar/asn1-ecc@^2.3.4';
export { RSAPublicKey } from 'npm:@peculiar/asn1-rsa@^2.3.4';
export { KeyDescription, id_ce_keyDescription } from 'npm:@peculiar/asn1-android@^2.3.3';
