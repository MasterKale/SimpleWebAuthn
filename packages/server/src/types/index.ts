// deno-fmt-ignore-file
/**
 * DO NOT MODIFY THESE FILES!
 *
 * These files were copied from the **types** package. To update this file, make changes to those
 * files instead and then run the following command from the monorepo root folder:
 *
 * deno task codegen:types
 */
// BEGIN CODEGEN
import type {
  AlgorithmIdentifier,
  AttestationConveyancePreference,
  AuthenticationExtensionsClientInputs,
  AuthenticationExtensionsClientOutputs,
  AuthenticatorAssertionResponse,
  AuthenticatorAttachment,
  AuthenticatorAttestationResponse,
  AuthenticatorSelectionCriteria,
  Base64URLString,
  COSEAlgorithmIdentifier,
  KeyUsage,
  PublicKeyCredential,
  PublicKeyCredentialCreationOptions,
  PublicKeyCredentialDescriptorJSON,
  PublicKeyCredentialParameters,
  PublicKeyCredentialRequestOptions,
  PublicKeyCredentialRpEntity,
  PublicKeyCredentialType,
  SubtleCrypto,
  UserVerificationRequirement,
} from './dom.ts';

export type {
  AlgorithmIdentifier,
  AttestationConveyancePreference,
  AuthenticationExtensionsClientInputs,
  AuthenticationExtensionsClientOutputs,
  AuthenticatorAssertionResponse,
  AuthenticatorAttachment,
  AuthenticatorAttestationResponse,
  AuthenticatorSelectionCriteria,
  AuthenticatorTransport,
  Base64URLString,
  COSEAlgorithmIdentifier,
  CredentialCreationOptions,
  CredentialRequestOptions,
  Crypto,
  PublicKeyCredential,
  PublicKeyCredentialCreationOptions,
  PublicKeyCredentialDescriptor,
  PublicKeyCredentialDescriptorJSON,
  PublicKeyCredentialParameters,
  PublicKeyCredentialRequestOptions,
  PublicKeyCredentialRpEntity,
  PublicKeyCredentialType,
  PublicKeyCredentialUserEntity,
  ResidentKeyRequirement,
  UserVerificationRequirement,
} from './dom.ts';

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
  hints?: PublicKeyCredentialHint[];
  attestation?: AttestationConveyancePreference;
  attestationFormats?: AttestationFormat[];
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
  hints?: PublicKeyCredentialHint[];
  extensions?: AuthenticationExtensionsClientInputs;
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
  response: AuthenticatorAttestationResponse;
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
  authenticatorData?: Base64URLString;
  // Optional in L2, but becomes required in L3. Play it safe until L3 becomes Recommendation
  transports?: string[];
  // Optional in L2, but becomes required in L3. Play it safe until L3 becomes Recommendation
  publicKeyAlgorithm?: COSEAlgorithmIdentifier;
  publicKey?: Base64URLString;
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
  userHandle?: Base64URLString;
}

/**
 * Public key credential information needed to verify authentication responses
 */
export type WebAuthnCredential = {
  id: Base64URLString;
  publicKey: Uint8Array_;
  // Number of times this authenticator is expected to have been used
  counter: number;
  // From browser's `startRegistration()` -> RegistrationCredential.response.transports (API L2 and up)
  transports?: string[];
};

/** */
export type PublicKeyCredentialJSON =
  | RegistrationResponseJSON
  | AuthenticationResponseJSON;

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
  toJSON(): PublicKeyCredentialJSON;
  // See https://w3c.github.io/webauthn/#sctn-getClientCapabilities
  getClientCapabilities?(): Promise<PublicKeyCredentialClientCapabilities>;
  // See https://w3c.github.io/webauthn/#sctn-signalUnknownCredential
  signalUnknownCredential(options: UnknownCredentialOptions): Promise<undefined>;
  // See https://w3c.github.io/webauthn/#sctn-signalAllAcceptedCredentials
  signalAllAcceptedCredentials(options: AllAcceptedCredentialsOptions): Promise<undefined>;
  // See https://w3c.github.io/webauthn/#sctn-signalCurrentUserDetails
  signalCurrentUserDetails(options: CurrentUserDetailsOptions): Promise<undefined>;
}

/**
 * The two types of credentials as defined by bit 3 ("Backup Eligibility") in authenticator data:
 * - `"singleDevice"` credentials will never be backed up
 * - `"multiDevice"` credentials can be backed up
 */
export type CredentialDeviceType = 'singleDevice' | 'multiDevice';

/**
 * Categories of authenticators that Relying Parties can pass along to browsers during
 * registration. Browsers that understand these values can optimize their modal experience to
 * start the user off in a particular registration flow:
 *
 * - `hybrid`: A platform authenticator on a mobile device
 * - `security-key`: A portable FIDO2 authenticator capable of being used on multiple devices via a USB or NFC connection
 * - `client-device`: The device that WebAuthn is being called on. Typically synonymous with platform authenticators
 *
 * See https://w3c.github.io/webauthn/#enumdef-publickeycredentialhint
 *
 * These values are less strict than `authenticatorAttachment`
 */
export type PublicKeyCredentialHint = 'hybrid' | 'security-key' | 'client-device';

/**
 * Values for an attestation object's `fmt`
 *
 * See https://www.iana.org/assignments/webauthn/webauthn.xhtml#webauthn-attestation-statement-format-ids
 */
export type AttestationFormat =
  | 'fido-u2f'
  | 'packed'
  | 'android-safetynet'
  | 'android-key'
  | 'tpm'
  | 'apple'
  | 'none';

/**
 * More specific values available from `PublicKeyCredential.getClientCapabilities()`.
 *
 * A capability with an `undefined` value does not mean the feature is unsupported. It may
 * simply be that the browser has chosen not to divulge its support for the capability as a more
 * specific determination may be factored into e.g. ad-tech's browser fingerprinting that violates
 * user privacy against the goals of the browser.
 *
 * See https://w3c.github.io/webauthn/#typedefdef-publickeycredentialclientcapabilities
 */
export type PublicKeyCredentialClientCapabilities = {
  conditionalCreate?: boolean;
  conditionalGet?: boolean;
  hybridTransport?: boolean;
  passkeyPlatformAuthenticator?: boolean;
  userVerifyingPlatformAuthenticator?: boolean;
  relatedOrigins?: boolean;
  signalAllAcceptedCredentials?: boolean;
  signalCurrentUserDetails?: boolean;
  signalUnknownCredential?: boolean;
};

/**
 * Equivalent to `Uint8Array` before TypeScript 5.7, and `Uint8Array<ArrayBuffer>` in TypeScript 5.7
 * and beyond.
 *
 * **Context**
 *
 * `Uint8Array` became a generic type in TypeScript 5.7, requiring types defined simply as
 * `Uint8Array` to be refactored to `Uint8Array<ArrayBuffer>` starting in Deno 2.2. `Uint8Array` is
 * _not_ generic in Deno 2.1.x and earlier, though, so this type helps bridge this gap.
 *
 * Inspired by Deno's std library:
 *
 * https://github.com/denoland/std/blob/b5a5fe4f96b91c1fe8dba5cc0270092dd11d3287/bytes/_types.ts#L11
 */
export type Uint8Array_ = ReturnType<Uint8Array['slice']>;

/**
 * Options for `PublicKeyCredential.signalUnknownCredential()`. This signal communicates that the
 * credential that the user just tried to register, or to authenticate with, was not one that the
 * Relying Party recognizes. The authenticator responsible for the credential can hide or delete
 * the credential so that the user does not see it in the future as an option to sign in with.
 *
 * It is a good idea for a Relying Party to send this signal immediately after the use of an
 * unrecognized credential. For example, after rejecting the output from `startRegistration()` due
 * to unsatisfied RP-specific authenticator registration policy; or after rejecting the output from
 * `startAuthentication()` because the user deleted the passkey from their RP-specific user
 * settings.
 *
 * See https://w3c.github.io/webauthn/#sctn-signalUnknownCredential for more info.
 */
type UnknownCredentialOptions = {
  rpId: string;
  credentialId: Base64URLString;
};

/**
 * Options for `PublicKeyCredential.signalAllAcceptedCredentials()`. This signal communicates the
 * current list of passkeys the Relying Party will recognize for use by the **authenticated** user
 * on the next login. Authenticators that have a passkey for (rpId + userId), but the passkey ID is
 * not found in allAcceptedCredentialIds, may choose to hide or delete the passkey because it will
 * not be accepted for use by the Relying Party.
 *
 * It is a good idea for a Relying Party to periodically send this signal, for example after every
 * successful authentication.
 *
 * See https://w3c.github.io/webauthn/#sctn-signalAllAcceptedCredentials for more info.
 */
type AllAcceptedCredentialsOptions = {
  rpId: string;
  userId: Base64URLString;
  allAcceptedCredentialIds: Base64URLString[];
};

/**
 * Options for `PublicKeyCredential.signalCurrentUserDetails()`. This signal that communicates a
 * change in the **authenticated** user's name and/or display name. This can help browsers and
 * platforms display the most up-to-date information about the user during a passkey authentication
 * instead of always showing whatever value was set at the time of registration.
 *
 * It is a good idea for a Relying Party to periodically send this signal, for example after every
 * successful authentication and immediately after the user name and/or display name is changed.
 *
 * See https://w3c.github.io/webauthn/#sctn-signalCurrentUserDetails for more info.
 */
type CurrentUserDetailsOptions = {
  rpId: string;
  userId: Base64URLString;
  name: string;
  displayName: string;
};

/**
 * Below are types for @simplewebauthn/browser's `sendSignal()` method. Shared out of here so that an RP
 * might use these same types in @simplewebauthn/server to type an API return value that can be
 * passed into `sendSignal()`
 */

/**
 * A signal that communicates that the credential that the user just tried to register, or to
 * authenticate with, was not one that the Relying Party recognizes. The authenticator responsible
 * for the credential can hide or delete the credential so that the user does not see it in the
 * future as an option to sign in with.
 *
 * It is a good idea for a Relying Party to send this signal immediately after the use of an
 * unrecognized credential. For example, after rejecting the output from `startRegistration()` due
 * to unsatisfied RP-specific authenticator registration policy; or after rejecting the output from
 * `startAuthentication()` because the user deleted the passkey from their RP-specific user
 * settings.
 *
 * See https://w3c.github.io/webauthn/#sctn-signalUnknownCredential for more info.
 */
export type SendSignalUnknownCredentialOpts = {
  signalName: 'unknownCredential';
  /** The same value used for `rpID` when calling \@simplewebauthn/server's `generateRegistrationOptions()` */
  rpID: string;
  /** The credential ID that the Relying Party didn't recognize for use */
  credentialID: Base64URLString;
};

/**
 * A signal that communicates the current list of passkeys the Relying Party will recognize for use
 * by the **authenticated** user on the next login. Authenticators that have a passkey for
 * (rpId + userId), but the passkey ID is not found in allAcceptedCredentialIds, may choose to hide
 * or delete the passkey because it will not be accepted for use by the Relying Party.
 *
 * It is a good idea for a Relying Party to periodically send this signal, for example after every
 * successful authentication.
 *
 * See https://w3c.github.io/webauthn/#sctn-signalAllAcceptedCredentials for more info.
 */
export type SendSignalAllAcceptedCredentialsOpts = {
  signalName: 'allAcceptedCredentials';
  /** The same value used for `rpID` when calling \@simplewebauthn/server's `generateRegistrationOptions()` */
  rpID: string;
  /** The base64url-encoded value used for `userID` when calling \@simplewebauthn/server's `generateRegistrationOptions()` */
  userID: Base64URLString;
  /** An array of base64url-encoded credential IDs for all credentials the user may use to authenticate */
  allAcceptedCredentialIDs: Base64URLString[];
};

/**
 * A signal that communicates a change in the **authenticated** user's name and/or display name.
 * This can help browsers and platforms display the most up-to-date information about the user
 * during a passkey authentication instead of always showing whatever value was set at the time of
 * registration.
 *
 * It is a good idea for a Relying Party to periodically send this signal, for example after every
 * successful authentication and immediately after the user name and/or display name is changed.
 *
 * See https://w3c.github.io/webauthn/#sctn-signalCurrentUserDetails for more info.
 */
export type SendSignalCurrentUserDetailsOpts = {
  signalName: 'currentUserDetails';
  /** The same value used for `rpID` when calling \@simplewebauthn/server's `generateRegistrationOptions()` */
  rpID: string;
  /** The base64url-encoded value used for `userID` when calling \@simplewebauthn/server's `generateRegistrationOptions()` */
  userID: Base64URLString;
  /** The primary account name, like an email address, username, etc... */
  userName: string;
  /** An optional, longer user identifier, like a full name, account differentiator, etc... Defaults to `""` */
  userDisplayName?: string;
};

/**
 * A super class of TypeScript's `SubtleCrypto` that knows about upcoming features
 */
export interface SubtleCryptoFuture extends SubtleCrypto {
  /** https://wicg.github.io/webcrypto-modern-algos/#SubtleCrypto-method-supports */
  supports(operation: KeyUsage, algorithm: AlgorithmIdentifier, length?: number): boolean;
}
