/**
 * @packageDocumentation
 * @module @simplewebauthn/typescript-types
 * @preferred
 */
/**
 * A variant of PublicKeyCredentialCreationOptions suitable for JSON transmission to the browser to
 * (eventually) get passed into navigator.credentials.create(...) in the browser.
 */
export interface PublicKeyCredentialCreationOptionsJSON extends Omit<
PublicKeyCredentialCreationOptions, 'challenge' | 'user' | 'excludeCredentials'
> {
  // Will be converted to a Uint8Array in the browser
  user: PublicKeyCredentialUserEntityJSON;
  challenge: Base64String;
  excludeCredentials: PublicKeyCredentialDescriptorJSON[];
}

/**
 * A variant of PublicKeyCredentialRequestOptions suitable for JSON transmission to the browser to
 * (eventually) get passed into navigator.credentials.get(...) in the browser.
 */
export interface PublicKeyCredentialRequestOptionsJSON extends Omit<
PublicKeyCredentialRequestOptions, 'challenge' |'allowCredentials'
> {
  // Will be converted to a Uint8Array in the browser
  challenge: Base64String;
  allowCredentials: PublicKeyCredentialDescriptorJSON[];
}

export interface PublicKeyCredentialDescriptorJSON extends Omit<
PublicKeyCredentialDescriptor, 'id'
> {
  // Should be a Base64-encoded credential ID. Will be converted to a Uint8Array in the browser
  id: Base64String;
}

export interface PublicKeyCredentialUserEntityJSON extends Omit <
PublicKeyCredentialUserEntity, 'id'
> {
  // Should be a Base64-encoded credential ID. Will be converted to a Uint8Array in the browser
  id: Base64String;
}

/**
 * The value returned from navigator.credentials.create()
 */
export interface AttestationCredential extends PublicKeyCredential {
  response: AuthenticatorAttestationResponse;
}

/**
 * A slightly-modified AttestationCredential to simplify working with ArrayBuffers that
 * are base64-encoded in the browser so that they can be sent as JSON to the server.
 */
export interface AttestationCredentialJSON
  extends Omit<AttestationCredential, 'response' | 'rawId'> {
  rawId: Base64String;
  response: AuthenticatorAttestationResponseJSON;
}

/**
 * The value returned from navigator.credentials.get()
 */
export interface AssertionCredential extends PublicKeyCredential {
  response: AuthenticatorAssertionResponse;
}

/**
 * A slightly-modified AssertionCredential to simplify working with ArrayBuffers that
 * are base64-encoded in the browser so that they can be sent as JSON to the server.
 */
export interface AssertionCredentialJSON extends Omit<AssertionCredential, 'response' | 'rawId'> {
  rawId: Base64String;
  response: AuthenticatorAssertionResponseJSON;
}

interface AuthenticatorAttestationResponseJSON
  extends Omit<AuthenticatorAttestationResponse, 'clientDataJSON' | 'attestationObject'> {
  clientDataJSON: Base64String;
  attestationObject: Base64String;
}

interface AuthenticatorAssertionResponseJSON
  extends Omit<
    AuthenticatorAssertionResponse,
    'authenticatorData' | 'clientDataJSON' | 'signature' | 'userHandle'
  > {
  authenticatorData: Base64String;
  clientDataJSON: Base64String;
  signature: Base64String;
  userHandle?: Base64String;
}

/**
 * A WebAuthn-compatible device and the information needed to verify assertions by it
 */
export type AuthenticatorDevice = {
  base64PublicKey: string;
  base64CredentialID: string;
  // Number of times this device is expected to have been used
  counter: number;
};

/**
 * An attempt to communicate that this isn't just any string, but a base64-encoded string
 */
export type Base64String = string;
