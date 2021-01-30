/**
 * @packageDocumentation
 * @module @simplewebauthn/typescript-types
 */

import type {
  AuthenticatorAssertionResponse,
  AuthenticatorAttestationResponse,
  AuthenticatorTransport,
  COSEAlgorithmIdentifier,
  PublicKeyCredential,
  PublicKeyCredentialCreationOptions,
  PublicKeyCredentialDescriptor,
  PublicKeyCredentialRequestOptions,
  PublicKeyCredentialUserEntity,
} from './dom';

export * from './dom';

/**
 * A variant of PublicKeyCredentialCreationOptions suitable for JSON transmission to the browser to
 * (eventually) get passed into navigator.credentials.create(...) in the browser.
 */
export interface PublicKeyCredentialCreationOptionsJSON
  extends Omit<PublicKeyCredentialCreationOptions, 'challenge' | 'user' | 'excludeCredentials'> {
  user: PublicKeyCredentialUserEntityJSON;
  challenge: Base64URLString;
  excludeCredentials: PublicKeyCredentialDescriptorJSON[];
  extensions?: CredentialCreationExtensionsInputJSON;
}

/**
 * A variant of PublicKeyCredentialRequestOptions suitable for JSON transmission to the browser to
 * (eventually) get passed into navigator.credentials.get(...) in the browser.
 */
export interface PublicKeyCredentialRequestOptionsJSON
  extends Omit<PublicKeyCredentialRequestOptions, 'challenge' | 'allowCredentials'> {
  challenge: Base64URLString;
  allowCredentials?: PublicKeyCredentialDescriptorJSON[];
  extensions?: CredentialRequestExtensionsInputJSON;
}

export interface PublicKeyCredentialDescriptorJSON
  extends Omit<PublicKeyCredentialDescriptor, 'id'> {
  id: Base64URLString;
}

export interface PublicKeyCredentialUserEntityJSON
  extends Omit<PublicKeyCredentialUserEntity, 'id'> {
  id: Base64URLString;
}

/**
 * The value returned from navigator.credentials.create()
 */
export interface AttestationCredential extends PublicKeyCredential {
  response: AuthenticatorAttestationResponseFuture;
}

/**
 * A slightly-modified AttestationCredential to simplify working with ArrayBuffers that
 * are Base64URL-encoded in the browser so that they can be sent as JSON to the server.
 */
export interface AttestationCredentialJSON
  extends Omit<AttestationCredential, 'response' | 'rawId' | 'getClientExtensionResults'> {
  rawId: Base64URLString;
  response: AuthenticatorAttestationResponseJSON;
  transports?: AuthenticatorTransport[];
  clientExtensionResults?: CredentialCreationExtensionsOutputJSON;
}

/**
 * The value returned from navigator.credentials.get()
 */
export interface AssertionCredential extends PublicKeyCredential {
  response: AuthenticatorAssertionResponse;
}

/**
 * A slightly-modified AssertionCredential to simplify working with ArrayBuffers that
 * are Base64URL-encoded in the browser so that they can be sent as JSON to the server.
 */
export interface AssertionCredentialJSON
  extends Omit<AssertionCredential, 'response' | 'rawId' | 'getClientExtensionResults'> {
  rawId: Base64URLString;
  response: AuthenticatorAssertionResponseJSON;
  clientExtensionResults?: CredentialRequestExtensionsOutputJSON;
}

/**
 * A slightly-modified AuthenticatorAttestationResponse to simplify working with ArrayBuffers that
 * are Base64URL-encoded in the browser so that they can be sent as JSON to the server.
 */
export interface AuthenticatorAttestationResponseJSON
  extends Omit<AuthenticatorAttestationResponseFuture, 'clientDataJSON' | 'attestationObject'> {
  clientDataJSON: Base64URLString;
  attestationObject: Base64URLString;
}

/**
 * A slightly-modified AuthenticatorAssertionResponse to simplify working with ArrayBuffers that
 * are Base64URL-encoded in the browser so that they can be sent as JSON to the server.
 */
export interface AuthenticatorAssertionResponseJSON
  extends Omit<
    AuthenticatorAssertionResponse,
    'authenticatorData' | 'clientDataJSON' | 'signature' | 'userHandle'
  > {
  authenticatorData: Base64URLString;
  clientDataJSON: Base64URLString;
  signature: Base64URLString;
  userHandle?: Base64URLString;
}

/**
 * A WebAuthn-compatible device and the information needed to verify assertions by it
 */
export type AuthenticatorDevice = {
  credentialPublicKey: Buffer;
  credentialID: Buffer;
  // Number of times this authenticator is expected to have been used
  counter: number;
  // From browser's `startAttestation()` -> AttestationCredentialJSON.transports (API L2 and up)
  transports?: AuthenticatorTransport[];
};

/**
 * An attempt to communicate that this isn't just any string, but a Base64URL-encoded string
 */
export type Base64URLString = string;

/**
 * AuthenticatorAttestationResponse in TypeScript's DOM lib is outdated (up through v3.9.7).
 * Maintain an augmented version here so we can implement additional properties as the WebAuthn
 * spec evolves.
 *
 * See https://www.w3.org/TR/webauthn-2/#iface-authenticatorattestationresponse
 *
 * Properties marked optional are not supported in all browsers.
 */
export interface AuthenticatorAttestationResponseFuture extends AuthenticatorAttestationResponse {
  getTransports?: () => AuthenticatorTransport[];
  getAuthenticatorData?: () => ArrayBuffer;
  getPublicKey?: () => ArrayBuffer;
  getPublicKeyAlgorithm?: () => COSEAlgorithmIdentifier[];
}

/**
 * Client Extensions - Attestation (Registration)
 */

export interface CredentialCreationExtensionsInputJSON {
  appidExclude?: string;
  uvm?: boolean;
  credProps?: boolean;
  prf?: {
    eval?: {
      first: Base64URLString;
      second?: Base64URLString;
    };
    evalByCredential?: {
      [base64CredID: string]: { first: Base64URLString; second?: Base64URLString };
    };
  };
}

export interface CredentialCreationExtensionsOutputJSON {
  appidExclude?: boolean;
  uvm?: Array<[number, number, number]>;
  credProps?: {
    rk: boolean;
  };
  prf?: {
    enabled?: boolean;
    results?: {
      first: Base64URLString;
      second?: Base64URLString;
    };
  };
}

/**
 * Client Extensions - Assertion (Authentication)
 */

export interface CredentialRequestExtensionsInputJSON {
  appid?: string;
  uvm?: boolean;
  prf?: {
    eval?: {
      first: Base64URLString;
      second?: Base64URLString;
    };
    evalByCredential?: {
      [base64CredID: string]: { first: Base64URLString; second?: Base64URLString };
    };
  };
  largeBlob?: {
    read?: boolean;
    write?: Base64URLString;
  };
}

export interface CredentialRequestExtensionsOutputJSON {
  appid?: boolean;
  uvm?: Array<[number, number, number]>;
  prf?: {
    enabled?: boolean;
    results?: {
      first: Base64URLString;
      second?: Base64URLString;
    };
  };
  largeBlob?: {
    blob?: Base64URLString;
    written?: boolean;
  };
}
