/**
 * @packageDocumentation
 * @module @simplewebauthn/typescript-types
 */

import type {
  AuthenticatorAssertionResponse,
  AuthenticatorAttestationResponse,
  PublicKeyCredential,
  PublicKeyCredentialDescriptor,
  AuthenticationExtensionsClientInputs,
  AuthenticationExtensionsClientOutputs,
  PublicKeyCredentialRpEntity,
  PublicKeyCredentialType,
  PublicKeyCredentialParameters,
  AuthenticatorSelectionCriteria,
  AttestationConveyancePreference,
  UserVerificationRequirement,
  AuthenticatorAttachment,
  PublicKeyCredentialCreationOptions,
  PublicKeyCredentialRequestOptions,
} from './dom';

export * from './dom';

/**
 * A variant of PublicKeyCredentialCreationOptions suitable for JSON transmission to the browser to
 * (eventually) get passed into navigator.credentials.create(...) in the browser.
 *
 * This should eventually get replaced with official TypeScript DOM types when WebAuthn L3 types
 * eventually make it into the language:
 *
 * https://w3c.github.io/webauthn/#dictdef-publickeycredentialcreationoptionsjson
 */
export interface PublicKeyCredentialCreationOptionsJSON {
  rp: PublicKeyCredentialRpEntity;
  user: PublicKeyCredentialUserEntityJSON;
  challenge: Base64URLString;
  pubKeyCredParams: PublicKeyCredentialParameters[];
  timeout?: number;
  excludeCredentials?: PublicKeyCredentialDescriptorJSON[];
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  attestation?: AttestationConveyancePreference;
  extensions?: AuthenticationExtensionsClientInputs;
}

/**
 * A variant of PublicKeyCredentialRequestOptions suitable for JSON transmission to the browser to
 * (eventually) get passed into navigator.credentials.get(...) in the browser.
 */
export interface PublicKeyCredentialRequestOptionsJSON {
  challenge: Base64URLString;
  timeout?: number;
  rpId?: string;
  allowCredentials?: PublicKeyCredentialDescriptorJSON[];
  userVerification?: UserVerificationRequirement;
  extensions?: AuthenticationExtensionsClientInputs;
}

/**
 * https://w3c.github.io/webauthn/#dictdef-publickeycredentialdescriptorjson
 */
export interface PublicKeyCredentialDescriptorJSON {
  id: Base64URLString;
  type: PublicKeyCredentialType;
  transports?: AuthenticatorTransportFuture[];
}

/**
 * https://w3c.github.io/webauthn/#dictdef-publickeycredentialuserentityjson
 */
export interface PublicKeyCredentialUserEntityJSON {
  id: string;
  name: string;
  displayName: string;
}

/**
 * The value returned from navigator.credentials.create()
 */
export interface RegistrationCredential extends PublicKeyCredentialFuture {
  response: AuthenticatorAttestationResponseFuture;
}

/**
 * A slightly-modified RegistrationCredential to simplify working with ArrayBuffers that
 * are Base64URL-encoded in the browser so that they can be sent as JSON to the server.
 *
 * https://w3c.github.io/webauthn/#dictdef-registrationresponsejson
 */
export interface RegistrationResponseJSON {
  id: Base64URLString;
  rawId: Base64URLString;
  response: AuthenticatorAttestationResponseJSON;
  authenticatorAttachment?: AuthenticatorAttachment;
  clientExtensionResults: AuthenticationExtensionsClientOutputs;
  type: PublicKeyCredentialType;
}

/**
 * The value returned from navigator.credentials.get()
 */
export interface AuthenticationCredential extends PublicKeyCredentialFuture {
  response: AuthenticatorAssertionResponse;
}

/**
 * A slightly-modified AuthenticationCredential to simplify working with ArrayBuffers that
 * are Base64URL-encoded in the browser so that they can be sent as JSON to the server.
 *
 * https://w3c.github.io/webauthn/#dictdef-authenticationresponsejson
 */
export interface AuthenticationResponseJSON {
  id: Base64URLString;
  rawId: Base64URLString;
  response: AuthenticatorAssertionResponseJSON;
  authenticatorAttachment?: AuthenticatorAttachment;
  clientExtensionResults: AuthenticationExtensionsClientOutputs;
  type: PublicKeyCredentialType;
}

/**
 * A slightly-modified AuthenticatorAttestationResponse to simplify working with ArrayBuffers that
 * are Base64URL-encoded in the browser so that they can be sent as JSON to the server.
 *
 * https://w3c.github.io/webauthn/#dictdef-authenticatorattestationresponsejson
 */
export interface AuthenticatorAttestationResponseJSON {
  clientDataJSON: Base64URLString;
  attestationObject: Base64URLString;
  // Optional in L2, but becomes required in L3. Play it safe until L3 becomes Recommendation
  transports?: AuthenticatorTransportFuture[];
}

/**
 * A slightly-modified AuthenticatorAssertionResponse to simplify working with ArrayBuffers that
 * are Base64URL-encoded in the browser so that they can be sent as JSON to the server.
 *
 * https://w3c.github.io/webauthn/#dictdef-authenticatorassertionresponsejson
 */
export interface AuthenticatorAssertionResponseJSON {
  clientDataJSON: Base64URLString;
  authenticatorData: Base64URLString;
  signature: Base64URLString;
  userHandle?: string;
}

/**
 * A WebAuthn-compatible device and the information needed to verify assertions by it
 */
export type AuthenticatorDevice = {
  credentialPublicKey: Uint8Array;
  credentialID: Uint8Array;
  // Number of times this authenticator is expected to have been used
  counter: number;
  // From browser's `startRegistration()` -> RegistrationCredentialJSON.transports (API L2 and up)
  transports?: AuthenticatorTransportFuture[];
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
  getTransports(): AuthenticatorTransportFuture[];
}

/**
 * A super class of TypeScript's `AuthenticatorTransport` that includes support for the latest
 * transports. Should eventually be replaced by TypeScript's when TypeScript gets updated to
 * know about it (sometime after 4.6.3)
 */
export type AuthenticatorTransportFuture = 'ble' | 'internal' | 'nfc' | 'usb' | 'cable' | 'hybrid';

/**
 * A super class of TypeScript's `PublicKeyCredentialDescriptor` that knows about the latest
 * transports. Should eventually be replaced by TypeScript's when TypeScript gets updated to
 * know about it (sometime after 4.6.3)
 */
export interface PublicKeyCredentialDescriptorFuture
  extends Omit<PublicKeyCredentialDescriptor, 'transports'> {
  transports?: AuthenticatorTransportFuture[];
}

/**
 *
 */
export type PublicKeyCredentialJSON = RegistrationResponseJSON | AuthenticationResponseJSON;

/**
 * A super class of TypeScript's `PublicKeyCredential` that knows about upcoming WebAuthn features
 */
export interface PublicKeyCredentialFuture extends PublicKeyCredential {
  type: PublicKeyCredentialType;
  // See https://github.com/w3c/webauthn/issues/1745
  isConditionalMediationAvailable?(): Promise<boolean>;
  // See https://w3c.github.io/webauthn/#sctn-parseCreationOptionsFromJSON
  parseCreationOptionsFromJSON?(
    options: PublicKeyCredentialCreationOptionsJSON,
  ): PublicKeyCredentialCreationOptions;
  // See https://w3c.github.io/webauthn/#sctn-parseRequestOptionsFromJSON
  parseRequestOptionsFromJSON?(
    options: PublicKeyCredentialRequestOptionsJSON,
  ): PublicKeyCredentialRequestOptions;
  // See https://w3c.github.io/webauthn/#dom-publickeycredential-tojson
  toJSON?(): PublicKeyCredentialJSON;
}

/**
 * The two types of credentials as defined by bit 3 ("Backup Eligibility") in authenticator data:
 * - `"singleDevice"` credentials will never be backed up
 * - `"multiDevice"` credentials can be backed up
 */
export type CredentialDeviceType = 'singleDevice' | 'multiDevice';
