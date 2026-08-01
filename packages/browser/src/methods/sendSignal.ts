import type {
  PublicKeyCredentialFuture,
  SendSignalAllAcceptedCredentialsOpts,
  SendSignalCurrentUserDetailsOpts,
  SendSignalUnknownCredentialOpts,
} from '../types/index.ts';
import { identifySignalError } from '../helpers/identifySignalError.ts';

export type {
  SendSignalAllAcceptedCredentialsOpts,
  SendSignalCurrentUserDetailsOpts,
  SendSignalUnknownCredentialOpts,
} from '../types/index.ts';

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
