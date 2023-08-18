// @simplewebauthn/typescript-types
export type {
  AttestationConveyancePreference,
  AuthenticationExtensionsClientInputs,
  AuthenticationResponseJSON,
  AuthenticatorDevice,
  AuthenticatorSelectionCriteria,
  Base64URLString,
  COSEAlgorithmIdentifier,
  CredentialDeviceType,
  Crypto,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialDescriptorFuture,
  PublicKeyCredentialParameters,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
  UserVerificationRequirement,
} from "../../typescript-types/src/index.ts";

// cbor (a.k.a. cbor-x in Node land)
export * as cborx from "https://deno.land/x/cbor@v1.5.2/index.js";

// cross-fetch
export { default as crossFetch } from "https://esm.sh/v131/cross-fetch@4.0.0/es2021/cross-fetch.mjs";

// debug
export { default as debug } from "https://esm.sh/v131/debug@4.3.4/denonext/debug.mjs";
export type { Debugger } from "https://esm.sh/v131/@types/debug@4.1.8/index.d.ts";

// @peculiar libraries
export {
  AsnParser,
  AsnSerializer,
} from "https://esm.sh/v131/@peculiar/asn1-schema@2.3.6/denonext/asn1-schema.mjs";
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
} from "https://esm.sh/v131/@peculiar/asn1-x509@2.3.6/es2021/asn1-x509.mjs";
export {
  ECDSASigValue,
  ECParameters,
  id_ecPublicKey,
  id_secp256r1,
  id_secp384r1,
} from "https://esm.sh/v131/@peculiar/asn1-ecc@2.3.6/es2021/asn1-ecc.mjs";
export { RSAPublicKey } from "https://esm.sh/v131/@peculiar/asn1-rsa@2.3.6/es2021/asn1-rsa.mjs";
export {
  id_ce_keyDescription,
  KeyDescription,
} from "https://esm.sh/v131/@peculiar/asn1-android@2.3.6/es2021/asn1-android.mjs";
