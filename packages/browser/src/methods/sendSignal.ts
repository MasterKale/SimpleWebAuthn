import type { Base64URLString, PublicKeyCredentialFuture } from '../types/index.ts';
import { identifySignalError } from '../helpers/identifySignalError.ts';

/**
 * Broadcast a passkey state change on the server to the browser to enlist the browser's help
 * in propagating that change to the corresponding authenticator. This can help prevent phantom
 * credentials from being offered for use, and enable new usernames to be displayed after a
 * passkey's creation.
 *
 * Sending a signal **does not** guarantee that the signal will be received by the authenticator.
 * Signals are a "fire and forget" type of broadcast that will have browsers making a best effort
 * to propagate the signal to the relevant authenticator. See the descriptions of the various
 * signal option types for guidance on how often a signal may need to be resent for maximum
 * efficacy.
 */
export async function sendSignal(
  opts:
    | SendSignalUnknownCredentialOpts
    | SendSignalAllAcceptedCredentialsOpts
    | SendSignalCurrentUserDetailsOpts,
): Promise<undefined> {
  const { signalName } = opts;

  if (signalName === 'unknownCredential') {
    return _callSignalUnknownCredential(opts);
  } else if (signalName === 'allAcceptedCredentials') {
    return _callSignalAllAcceptedCredentials(opts);
  } else if (signalName === 'currentUserDetails') {
    return _callSignalCurrentUserDetails(opts);
  }

  // @ts-ignore: this should never happen, but just in case
  throw new Error(`Received unrecognized signalName "${opts.signalName}"`);
}

/**
 * Wrapper for PublicKeyCredential.signalUnknownCredential()
 */
async function _callSignalUnknownCredential(opts: SendSignalUnknownCredentialOpts) {
  const globalPublicKeyCredential = globalThis
    .PublicKeyCredential as unknown as PublicKeyCredentialFuture;

  if (typeof globalPublicKeyCredential.signalUnknownCredential !== 'function') {
    throw new Error('This browser does not support PublicKeyCredential.signalUnknownCredential()');
  }

  try {
    await globalPublicKeyCredential.signalUnknownCredential({
      rpId: opts.rpID,
      credentialId: opts.credentialID,
    });
  } catch (err) {
    throw identifySignalError({ error: err as Error, options: opts });
  }

  return undefined;
}

/**
 * Wrapper for PublicKeyCredential.signalAllAcceptedCredentials()
 */
async function _callSignalAllAcceptedCredentials(opts: SendSignalAllAcceptedCredentialsOpts) {
  const globalPublicKeyCredential = globalThis
    .PublicKeyCredential as unknown as PublicKeyCredentialFuture;

  if (typeof globalPublicKeyCredential.signalAllAcceptedCredentials !== 'function') {
    throw new Error(
      'This browser does not support PublicKeyCredential.signalAllAcceptedCredentials()',
    );
  }

  try {
    await globalPublicKeyCredential.signalAllAcceptedCredentials({
      rpId: opts.rpID,
      userId: opts.userID,
      allAcceptedCredentialIds: opts.allAcceptedCredentialIDs,
    });
  } catch (err) {
    throw identifySignalError({ error: err as Error, options: opts });
  }

  return undefined;
}

/**
 * Wrapper for PublicKeyCredential.signalAllAcceptedCredentials()
 */
async function _callSignalCurrentUserDetails(opts: SendSignalCurrentUserDetailsOpts) {
  const globalPublicKeyCredential = globalThis
    .PublicKeyCredential as unknown as PublicKeyCredentialFuture;

  if (typeof globalPublicKeyCredential.signalCurrentUserDetails !== 'function') {
    throw new Error(
      'This browser does not support PublicKeyCredential.signalCurrentUserDetails()',
    );
  }

  try {
    await globalPublicKeyCredential.signalCurrentUserDetails({
      rpId: opts.rpID,
      userId: opts.userID,
      name: opts.userName,
      displayName: opts.userDisplayName ?? '',
    });
  } catch (err) {
    throw identifySignalError({ error: err as Error, options: opts });
  }

  return undefined;
}

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
