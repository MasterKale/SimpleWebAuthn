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
  user: PublicKeyCredentialUserEntityJSON;
  challenge: Base64URLString;
  excludeCredentials: PublicKeyCredentialDescriptorJSON[];
}

/**
 * A variant of PublicKeyCredentialRequestOptions suitable for JSON transmission to the browser to
 * (eventually) get passed into navigator.credentials.get(...) in the browser.
 */
export interface PublicKeyCredentialRequestOptionsJSON extends Omit<
PublicKeyCredentialRequestOptions, 'challenge' |'allowCredentials'
> {
  challenge: Base64URLString;
  allowCredentials: PublicKeyCredentialDescriptorJSON[];
}

export interface PublicKeyCredentialDescriptorJSON extends Omit<
PublicKeyCredentialDescriptor, 'id'
> {
  id: Base64URLString;
}

export interface PublicKeyCredentialUserEntityJSON extends Omit <
PublicKeyCredentialUserEntity, 'id'
> {
  id: Base64URLString;
}

/**
 * The value returned from navigator.credentials.create()
 */
export interface AttestationCredential extends PublicKeyCredential {
  response: AuthenticatorAttestationResponse;
}

/**
 * A slightly-modified AttestationCredential to simplify working with ArrayBuffers that
 * are base64url-encoded in the browser so that they can be sent as JSON to the server.
 */
export interface AttestationCredentialJSON
  extends Omit<AttestationCredential, 'response' | 'rawId' | 'getClientExtensionResults'> {
  rawId: Base64URLString;
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
 * are base64url-encoded in the browser so that they can be sent as JSON to the server.
 */
export interface AssertionCredentialJSON
  extends Omit<AssertionCredential, 'response' | 'rawId' | 'getClientExtensionResults'> {
  rawId: Base64URLString;
  response: AuthenticatorAssertionResponseJSON;
}

interface AuthenticatorAttestationResponseJSON
  extends Omit<AuthenticatorAttestationResponse, 'clientDataJSON' | 'attestationObject'> {
  clientDataJSON: Base64URLString;
  attestationObject: Base64URLString;
}

interface AuthenticatorAssertionResponseJSON
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
  publicKey: Base64URLString;
  credentialID: Base64URLString;
  // Number of times this device is expected to have been used
  counter: number;
};

/**
 * An attempt to communicate that this isn't just any string, but a base64url-encoded string
 */
export type Base64URLString = string;
