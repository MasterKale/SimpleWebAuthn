// @simplewebauthn/types
export type {
  AttestationConveyancePreference,
  AuthenticationExtensionsClientInputs,
  AuthenticationResponseJSON,
  AuthenticatorDevice,
  AuthenticatorSelectionCriteria,
  AuthenticatorTransportFuture,
  Base64URLString,
  COSEAlgorithmIdentifier,
  CredentialDeviceType,
  Crypto,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialParameters,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
  UserVerificationRequirement,
} from '../../types/src/index.ts';

// tiny_cbor (a.k.a. tiny-cbor in Node land)
export * as tinyCbor from 'https://deno.land/x/tiny_cbor@0.2.2/index.ts';

// b64 (a.k.a. @hexagon/base64 in Node land)
export { default as base64 } from 'https://deno.land/x/b64@1.1.27/src/base64.js';

// cross-fetch
export { fetch as crossFetch } from 'https://esm.sh/cross-fetch@4.0.0';

// @peculiar libraries
export { AsnParser, AsnSerializer, OctetString } from 'https://esm.sh/@peculiar/asn1-schema@2.3.8';
export {
  AuthorityKeyIdentifier,
  BasicConstraints,
  Certificate,
  CertificateList,
  CRLDistributionPoints,
  ExtendedKeyUsage,
  Extensions,
  id_ce_authorityKeyIdentifier,
  id_ce_basicConstraints,
  id_ce_cRLDistributionPoints,
  id_ce_extKeyUsage,
  id_ce_subjectAltName,
  id_ce_subjectKeyIdentifier,
  Name,
  SubjectAlternativeName,
  SubjectKeyIdentifier,
} from 'https://esm.sh/@peculiar/asn1-x509@2.3.8';
export {
  ECDSASigValue,
  ECParameters,
  id_ecPublicKey,
  id_secp256r1,
  id_secp384r1,
} from 'https://esm.sh/@peculiar/asn1-ecc@2.3.8';
export { RSAPublicKey } from 'https://esm.sh/@peculiar/asn1-rsa@2.3.8';
export { id_ce_keyDescription, KeyDescription } from 'https://esm.sh/@peculiar/asn1-android@2.3.10';
