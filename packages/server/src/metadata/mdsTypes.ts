import { Base64URLString } from '@simplewebauthn/typescript-types';

import { FIDO_AUTHENTICATOR_STATUS } from '../helpers/constants';

/**
 * Parsed JWT structures
 */
export type MDSJWTHeader = {
  alg: string;
  typ: string;
  x5c: Base64URLString[];
};

export type MDSJWTPayload = {
  legalHeader: string;
  no: number;
  nextUpdate: string; // YYYY-MM-DD
  entries: MDSEntry[];
};

export type MDSEntry = {
  attestationCertificateKeyIdentifiers?: string[];
  metadataStatement: MetadataStatement;
  statusReports: {
    status: FIDO_AUTHENTICATOR_STATUS;
    certificateNumber: string;
    certificate: string;
    certificationDescriptor: string;
    url: string;
    certificationRequirementsVersion: string;
    certificationPolicyVersion: string;
    // YYYY-MM-DD
    effectiveDate: string;
  }[];
  // YYYY-MM-DD
  timeOfLastStatusChange: string;
};

/**
 * Types defined in the FIDO Metadata Statement spec
 *
 * See https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html
 */
type CodeAccuracyDescriptor = {
  base: number;
  minLength: number;
  maxRetries?: number;
  blockSlowdown?: number;
};

type BiometricAccuracyDescriptor = {
  selfAttestedFRR?: number;
  selfAttestedFAR?: number;
  maxTemplates?: number;
  maxRetries?: number;
  blockSlowdown?: number;
};

type PatternAccuracyDescriptor = {
  minComplexity: number;
  maxRetries?: number;
  blockSlowdown?: number;
};

type VerificationMethodDescriptor = {
  userVerificationMethod: UserVerify;
  caDesc?: CodeAccuracyDescriptor;
  baDesc?: BiometricAccuracyDescriptor;
  paDesc?: PatternAccuracyDescriptor;
};

type VerificationMethodANDCombinations = VerificationMethodDescriptor[];

type rgbPaletteEntry = {
  r: number;
  g: number;
  b: number;
};

type DisplayPNGCharacteristicsDescriptor = {
  width: number;
  height: number;
  bitDepth: number;
  colorType: number;
  compression: number;
  filter: number;
  interlace: number;
  plte?: rgbPaletteEntry[];
};

type EcdaaTrustAnchor = {
  X: string;
  Y: string;
  c: string;
  sx: string;
  sy: string;
  G1Curve: string;
};

type ExtensionDescriptor = {
  id: string;
  tag?: number;
  data?: string;
  fail_if_unknown: boolean;
};

// langCode -> "en-US", "ja-JP", etc...
type AlternativeDescriptions = { [langCode: string]: string };

export type MetadataStatement = {
  legalHeader?: string;
  aaid?: string;
  aaguid?: string;
  attestationCertificateKeyIdentifiers?: string[];
  description: string;
  alternativeDescriptions?: AlternativeDescriptions;
  authenticatorVersion: number;
  protocolFamily: string;
  schema: number;
  upv: Version[];
  authenticationAlgorithms: AlgSign[];
  publicKeyAlgAndEncodings: AlgKey[];
  attestationTypes: Attestation[];
  userVerificationDetails: VerificationMethodANDCombinations[];
  keyProtection: KeyProtection[];
  isKeyRestricted?: boolean;
  isFreshUserVerificationRequired?: boolean;
  matcherProtection: MatcherProtection[];
  cryptoStrength?: number;
  attachmentHint?: AttachmentHint[];
  tcDisplay: TransactionConfirmationDisplay[];
  tcDisplayContentType?: string;
  tcDisplayPNGCharacteristics?: DisplayPNGCharacteristicsDescriptor[];
  attestationRootCertificates: string[];
  ecdaaTrustAnchors?: EcdaaTrustAnchor[];
  icon?: string;
  supportedExtensions?: ExtensionDescriptor[];
  authenticatorGetInfo?: AuthenticatorGetInfo;
};

/**
 * Types declared in other specs
 */

/**
 * USER_VERIFY
 * https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#user-verification-methods
 */
type UserVerify =
  | 'presence_internal'
  | 'fingerprint_internal'
  | 'passcode_internal'
  | 'voiceprint_internal'
  | 'faceprint_internal'
  | 'location_internal'
  | 'eyeprint_internal'
  | 'pattern_internal'
  | 'handprint_internal'
  | 'passcode_external'
  | 'pattern_external'
  | 'none'
  | 'all';

/**
 * ALG_SIGN
 * https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#authentication-algorithms
 */
type AlgSign =
  | 'secp256r1_ecdsa_sha256_raw'
  | 'secp256r1_ecdsa_sha256_der'
  | 'rsassa_pss_sha256_raw'
  | 'rsassa_pss_sha256_der'
  | 'secp256k1_ecdsa_sha256_raw'
  | 'secp256k1_ecdsa_sha256_der'
  | 'sm2_sm3_raw'
  | 'rsa_emsa_pkcs1_sha256_raw'
  | 'rsa_emsa_pkcs1_sha256_der'
  | 'rsassa_pss_sha384_raw'
  | 'rsassa_pss_sha256_raw'
  | 'rsassa_pkcsv15_sha256_raw'
  | 'rsassa_pkcsv15_sha384_raw'
  | 'rsassa_pkcsv15_sha512_raw'
  | 'rsassa_pkcsv15_sha1_raw'
  | 'secp384r1_ecdsa_sha384_raw'
  | 'secp512r1_ecdsa_sha256_raw'
  | 'ed25519_eddsa_sha512_raw';

/**
 * ALG_KEY
 * https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#public-key-representation-formats
 */
type AlgKey = 'ecc_x962_raw' | 'ecc_x962_der' | 'rsa_2048_raw' | 'rsa_2048_der' | 'cose';

/**
 * ATTESTATION
 * https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#authenticator-attestation-types
 */
type Attestation = 'basic_full' | 'basic_surrogate' | 'ecdaa' | 'attca';

/**
 * KEY_PROTECTION
 * https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#key-protection-types
 */
type KeyProtection = 'software' | 'hardware' | 'tee' | 'secure_element' | 'remote_handle';

/**
 * MATCHER_PROTECTION
 * https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#matcher-protection-types
 */
type MatcherProtection = 'software' | 'tee' | 'on_chip';

/**
 * ATTACHMENT_HINT
 * https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#authenticator-attachment-hints
 */
type AttachmentHint =
  | 'internal'
  | 'external'
  | 'wired'
  | 'wireless'
  | 'nfc'
  | 'bluetooth'
  | 'network'
  | 'ready'
  | 'wifi_direct';

/**
 * TRANSACTION_CONFIRMATION_DISPLAY
 * https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#transaction-confirmation-display-types
 */
type TransactionConfirmationDisplay = 'any' | 'privileged_software' | 'tee' | 'hardware' | 'remote';

/**
 * https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-protocol-v1.2-ps-20201020.html#version-interface
 */
type Version = {
  major: number;
  minor: number;
};

/**
 * https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetInfoz
 */
type AuthenticatorGetInfo = {
  versions: ('FIDO_2_0' | 'U2F_V2')[];
  extensions?: string[];
  aaguid: string;
  options?: {
    plat?: boolean;
    rk?: boolean;
    clientPin?: boolean;
    up?: boolean;
    uv?: boolean;
  };
  maxMsgSize?: number;
  pinProtocols?: number[];
};
